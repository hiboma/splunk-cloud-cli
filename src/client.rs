use crate::auth::Authorizer;
use crate::config::Credentials;
use crate::error::{Result, SplunkError};
use reqwest::{Method, StatusCode};
use serde_json::Value;

/// Splunk Cloud の REST API を叩く薄いクライアント。
///
/// - `output_mode=json` を自動付与する（GET/POST 双方）
/// - `Authorization` ヘッダは `Authorizer` から取得する
/// - 自己署名は受け付けない（`rustls-tls` の既定に従う）
#[derive(Debug, Clone)]
pub struct SplunkClient {
    http: reqwest::Client,
    base_url: String,
    auth: Authorizer,
    pub default_app: String,
    pub default_user: String,
    debug: bool,
}

impl SplunkClient {
    pub fn new(creds: Credentials) -> Result<Self> {
        Self::new_with_debug(creds, false)
    }

    pub fn new_with_debug(creds: Credentials, debug: bool) -> Result<Self> {
        let base_url = creds.base_url.clone();
        if !base_url.starts_with("https://") && !Self::is_loopback_http(&base_url) {
            return Err(SplunkError::Config(format!(
                "base_url must use HTTPS (got: {}). HTTP is only allowed for localhost and 127.0.0.1.",
                base_url
            )));
        }
        let http = reqwest::Client::builder()
            .user_agent(concat!("splunk-cloud-cli/", env!("CARGO_PKG_VERSION")))
            .build()?;
        let auth = Authorizer::new(&creds, http.clone());
        Ok(Self {
            http,
            base_url,
            auth,
            default_app: creds.default_app,
            default_user: creds.default_user,
            debug,
        })
    }

    /// `servicesNS/{user}/{app}/` の namespace 付きパスを組み立てる。
    pub fn ns_path(&self, user: Option<&str>, app: Option<&str>, path: &str) -> String {
        let user = user.unwrap_or(&self.default_user);
        let app = app.unwrap_or(&self.default_app);
        format!(
            "/servicesNS/{}/{}/{}",
            user,
            app,
            path.trim_start_matches('/')
        )
    }

    /// リソース名を URL エンコードする。`name` には `/` を含めないことを仮定する。
    pub fn encode(name: &str) -> String {
        urlencoding::encode(name).into_owned()
    }

    /// `http://localhost` / `http://127.0.0.1` のみ許容する判定。
    fn is_loopback_http(url: &str) -> bool {
        for prefix in &["http://localhost", "http://127.0.0.1"] {
            if let Some(rest) = url.strip_prefix(prefix) {
                if rest.is_empty() || rest.starts_with(':') || rest.starts_with('/') {
                    return true;
                }
            }
        }
        false
    }

    /// GET を JSON で返す。
    pub async fn get(&self, path: &str, query: &[(&str, &str)]) -> Result<Value> {
        self.request_json(Method::GET, path, query, None).await
    }

    /// GET を bytes で返す。バイナリ応答用。
    #[allow(dead_code)]
    pub async fn get_bytes(&self, path: &str, query: &[(&str, &str)]) -> Result<Vec<u8>> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self.send(Method::GET, &url, query, None, false).await?;
        if resp.status() == StatusCode::UNAUTHORIZED {
            self.auth.invalidate().await;
            let retry = self.send(Method::GET, &url, query, None, true).await?;
            return handle_bytes(retry).await;
        }
        handle_bytes(resp).await
    }

    /// POST application/x-www-form-urlencoded。
    pub async fn post_form(&self, path: &str, form: &[(&str, &str)]) -> Result<Value> {
        let owned: Vec<(String, String)> = form
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        self.request_json(Method::POST, path, &[], Some(Body::Form(owned)))
            .await
    }

    /// POST application/x-www-form-urlencoded。
    /// 4xx でも JSON ボディが取れれば `(status, value)` を返す。
    /// 5xx・タイムアウト・JSON パース失敗は通常通り `Err` を返す。
    /// 構文エラーでも `messages[]` を返す `/services/search/parser` のような
    /// エンドポイントを呼び出すために使う。
    pub async fn post_form_allow_error(
        &self,
        path: &str,
        form: &[(&str, &str)],
    ) -> Result<(StatusCode, Value)> {
        let owned: Vec<(String, String)> = form
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let url = format!("{}{}", self.base_url, path);
        let body = Some(Body::Form(owned));
        let resp = self
            .send(Method::POST, &url, &[], body.clone(), false)
            .await?;
        let resp = if resp.status() == StatusCode::UNAUTHORIZED {
            self.auth.invalidate().await;
            self.send(Method::POST, &url, &[], body, true).await?
        } else {
            resp
        };
        let (status, text) = self.drain_response(resp).await?;
        if status.is_server_error() {
            return Err(api_error(status, &text));
        }
        let value = if text.is_empty() {
            Value::Null
        } else {
            match serde_json::from_str::<Value>(&text) {
                Ok(v) => v,
                Err(_) if !status.is_success() => return Err(api_error(status, &text)),
                Err(e) => return Err(SplunkError::Json(e)),
            }
        };
        Ok((status, value))
    }

    /// POST application/x-www-form-urlencoded。`query` も付与する。
    #[allow(dead_code)]
    pub async fn post_form_with_query(
        &self,
        path: &str,
        query: &[(&str, &str)],
        form: &[(&str, &str)],
    ) -> Result<Value> {
        let owned: Vec<(String, String)> = form
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        self.request_json(Method::POST, path, query, Some(Body::Form(owned)))
            .await
    }

    /// POST application/json。
    pub async fn post_json(&self, path: &str, body: &Value) -> Result<Value> {
        self.request_json(Method::POST, path, &[], Some(Body::Json(body.clone())))
            .await
    }

    /// POST application/json に query 付き。
    #[allow(dead_code)]
    pub async fn post_json_with_query(
        &self,
        path: &str,
        query: &[(&str, &str)],
        body: &Value,
    ) -> Result<Value> {
        self.request_json(Method::POST, path, query, Some(Body::Json(body.clone())))
            .await
    }

    /// DELETE。
    pub async fn delete(&self, path: &str) -> Result<Value> {
        self.request_json(Method::DELETE, path, &[], None).await
    }

    /// GET をストリーミングで受け取り、各行を callback に渡す。
    /// Splunk の `search/jobs/export` は chunked で JSON Lines を返す。
    pub async fn get_stream_lines<F>(
        &self,
        path: &str,
        query: &[(&str, &str)],
        mut on_line: F,
    ) -> Result<()>
    where
        F: FnMut(&str) -> Result<()>,
    {
        use tokio::io::AsyncBufReadExt;
        let url = format!("{}{}", self.base_url, path);
        let resp = self.send(Method::GET, &url, query, None, false).await?;

        let resp = if resp.status() == StatusCode::UNAUTHORIZED {
            self.auth.invalidate().await;
            self.send(Method::GET, &url, query, None, true).await?
        } else {
            resp
        };

        let status = resp.status();
        if !status.is_success() {
            let mut body = resp.text().await.unwrap_or_default();
            body.truncate(500);
            return Err(SplunkError::Api(format!("{}: {}", status, body)));
        }

        let stream = resp.bytes_stream();
        use futures_util::TryStreamExt;
        let reader = tokio_util::io::StreamReader::new(stream.map_err(std::io::Error::other));
        let mut lines = tokio::io::BufReader::new(reader).lines();
        while let Some(line) = lines.next_line().await? {
            on_line(&line)?;
        }
        Ok(())
    }

    async fn request_json(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<Body>,
    ) -> Result<Value> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .send(method.clone(), &url, query, body.clone(), false)
            .await?;

        // 401 だった場合だけ、一度だけリトライ。
        if resp.status() == StatusCode::UNAUTHORIZED {
            self.auth.invalidate().await;
            let retry = self.send(method, &url, query, body, true).await?;
            return self.handle_response(retry).await;
        }
        self.handle_response(resp).await
    }

    async fn send(
        &self,
        method: Method,
        url: &str,
        query: &[(&str, &str)],
        body: Option<Body>,
        is_retry: bool,
    ) -> Result<reqwest::Response> {
        let mut query: Vec<(String, String)> = query
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        if !query.iter().any(|(k, _)| k == "output_mode") {
            query.push(("output_mode".into(), "json".into()));
        }

        let headers = self.auth.auth_header().await?;
        if self.debug {
            self.debug_log_request(&method, url, &query, &headers, body.as_ref(), is_retry);
        }
        let mut req = self
            .http
            .request(method, url)
            .headers(headers)
            .query(&query);
        if let Some(b) = body {
            req = match b {
                Body::Form(form) => req.form(&form),
                Body::Json(json) => req.json(&json),
            };
        }
        Ok(req.send().await?)
    }

    fn debug_log_request(
        &self,
        method: &Method,
        url: &str,
        query: &[(String, String)],
        headers: &reqwest::header::HeaderMap,
        body: Option<&Body>,
        is_retry: bool,
    ) {
        let tag = if is_retry {
            "[debug][retry]"
        } else {
            "[debug]"
        };
        eprintln!("{} {} {}", tag, method, url);
        if !query.is_empty() {
            eprintln!(
                "{}   query: {}",
                tag,
                query
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join("&")
            );
        }
        for (name, value) in headers.iter() {
            let redacted = if name.as_str().eq_ignore_ascii_case("authorization") {
                let len = value.as_bytes().len();
                let scheme = value
                    .to_str()
                    .unwrap_or("")
                    .split_whitespace()
                    .next()
                    .unwrap_or("<?>");
                format!("{} <redacted:{} bytes>", scheme, len)
            } else {
                value.to_str().unwrap_or("<binary>").to_string()
            };
            eprintln!("{}   {}: {}", tag, name, redacted);
        }
        if let Some(b) = body {
            match b {
                Body::Form(form) => {
                    let preview = form
                        .iter()
                        .map(|(k, v)| {
                            if k == "password" {
                                format!("{}=<redacted>", k)
                            } else {
                                format!("{}={}", k, v)
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("&");
                    eprintln!("{}   form body: {}", tag, preview);
                }
                Body::Json(json) => {
                    let mut s = serde_json::to_string(json).unwrap_or_default();
                    if s.len() > 500 {
                        s.truncate(500);
                        s.push_str("...");
                    }
                    eprintln!("{}   json body: {}", tag, s);
                }
            }
        }
    }

    async fn handle_response(&self, resp: reqwest::Response) -> Result<Value> {
        let (status, text) = self.drain_response(resp).await?;
        if !status.is_success() {
            return Err(api_error(status, &text));
        }
        if text.is_empty() {
            return Ok(Value::Null);
        }
        Ok(serde_json::from_str(&text)?)
    }

    /// レスポンスを読み尽くして `(status, body)` を返す。
    /// `self.debug` 有効時はステータス・ヘッダ・本文プレビューを stderr に出す。
    async fn drain_response(&self, resp: reqwest::Response) -> Result<(StatusCode, String)> {
        let status = resp.status();
        let headers = resp.headers().clone();
        let text = resp.text().await?;
        if self.debug {
            eprintln!("[debug] <- {}", status);
            for (name, value) in headers.iter() {
                eprintln!(
                    "[debug]   {}: {}",
                    name,
                    value.to_str().unwrap_or("<binary>")
                );
            }
            let preview = preview_body(&text, 1024);
            eprintln!("[debug]   body: {}", preview);
        }
        Ok((status, text))
    }
}

/// debug 出力用に本文を一定バイト数で切り詰める。
fn preview_body(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        text.to_string()
    } else {
        format!("{}...", &text[..limit])
    }
}

/// 非 2xx 応答を `SplunkError::Api` に変換する共通ヘルパ。
/// 本文は 500 バイトで打ち切る。
fn api_error(status: StatusCode, text: &str) -> SplunkError {
    let truncated = if text.len() > 500 { &text[..500] } else { text };
    SplunkError::Api(format!("{}: {}", status, truncated))
}

#[derive(Debug, Clone)]
enum Body {
    Form(Vec<(String, String)>),
    Json(Value),
}

#[allow(dead_code)]
async fn handle_bytes(resp: reqwest::Response) -> Result<Vec<u8>> {
    let status = resp.status();
    if !status.is_success() {
        let mut body = resp.text().await.unwrap_or_default();
        body.truncate(500);
        return Err(SplunkError::Api(format!("{}: {}", status, body)));
    }
    Ok(resp.bytes().await?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthMethod, Credentials};

    fn test_client(default_user: &str, default_app: &str) -> SplunkClient {
        let creds = Credentials {
            base_url: "https://example.splunkcloud.com:8089".to_string(),
            auth: AuthMethod::BearerToken("dummy".to_string()),
            default_app: default_app.to_string(),
            default_user: default_user.to_string(),
        };
        SplunkClient::new(creds).unwrap()
    }

    #[test]
    fn ns_path_uses_defaults_when_none() {
        let c = test_client("nobody", "search");
        assert_eq!(
            c.ns_path(None, None, "data/ui/views"),
            "/servicesNS/nobody/search/data/ui/views"
        );
    }

    #[test]
    fn ns_path_allows_wildcard_dash() {
        let c = test_client("-", "-");
        assert_eq!(
            c.ns_path(None, None, "data/ui/views"),
            "/servicesNS/-/-/data/ui/views"
        );
    }

    #[test]
    fn ns_path_trims_leading_slash_in_subpath() {
        let c = test_client("nobody", "search");
        assert_eq!(
            c.ns_path(None, None, "/saved/searches"),
            "/servicesNS/nobody/search/saved/searches"
        );
    }

    #[test]
    fn ns_path_explicit_overrides_default() {
        let c = test_client("nobody", "search");
        assert_eq!(
            c.ns_path(Some("admin"), Some("my_app"), "data/ui/views"),
            "/servicesNS/admin/my_app/data/ui/views"
        );
    }

    #[test]
    fn preview_body_leaves_short_text_intact() {
        assert_eq!(preview_body("hello", 1024), "hello");
    }

    #[test]
    fn preview_body_truncates_long_text() {
        let long: String = "x".repeat(2000);
        let p = preview_body(&long, 1024);
        assert_eq!(p.len(), 1024 + "...".len());
        assert!(p.ends_with("..."));
    }

    #[test]
    fn api_error_truncates_at_500_bytes() {
        let long: String = "y".repeat(800);
        let err = api_error(StatusCode::BAD_REQUEST, &long);
        let msg = format!("{}", err);
        assert!(msg.contains("400"));
        assert!(msg.contains(&"y".repeat(500)));
        assert!(!msg.contains(&"y".repeat(501)));
    }
}

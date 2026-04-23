use crate::config::{AuthMethod, Credentials};
use crate::error::{Result, SplunkError};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::RwLock;

/// `auth` モジュールは `AuthMethod` を HTTP Authorization ヘッダへ変換する責務を持つ。
///
/// `BearerToken` / `SessionKey` はそのままヘッダを組み立てるが、
/// `Basic` は `/services/auth/login` を叩いて得た session key をキャッシュする。
///
/// `Debug` は派生しない。`cached_session` には Splunk session key が載るため、
/// `#[derive(Debug)]` で `Arc<RwLock<Option<String>>>` の Debug に委譲すると
/// 値がそのまま展開される。`{:?}` / `dbg!` 経由の漏洩経路を潰すため手書きする。
#[derive(Clone)]
pub struct Authorizer {
    base_url: String,
    method: AuthMethod,
    cached_session: Arc<RwLock<Option<String>>>,
    http: reqwest::Client,
}

impl std::fmt::Debug for Authorizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `try_read` は非同期ランタイム外でも呼べる。取得失敗時でも値は展開しない。
        let cached = match self.cached_session.try_read() {
            Ok(guard) => match *guard {
                Some(_) => "Some(***)",
                None => "None",
            },
            Err(_) => "<locked>",
        };
        f.debug_struct("Authorizer")
            .field("base_url", &self.base_url)
            .field("method", &self.method)
            .field("cached_session", &cached)
            .finish()
    }
}

impl Authorizer {
    pub fn new(creds: &Credentials, http: reqwest::Client) -> Self {
        Self {
            base_url: creds.base_url.clone(),
            method: creds.auth.clone(),
            cached_session: Arc::new(RwLock::new(None)),
            http,
        }
    }

    /// 現在の認証方式に対応する Authorization ヘッダを構築する。
    pub async fn auth_header(&self) -> Result<HeaderMap> {
        let value = match &self.method {
            AuthMethod::BearerToken(t) => format!("Bearer {}", t),
            AuthMethod::SessionKey(sk) => format!("Splunk {}", sk),
            AuthMethod::Basic { username, password } => {
                let sk = self.login_if_needed(username, password).await?;
                format!("Splunk {}", sk)
            }
        };
        let mut headers = HeaderMap::new();
        let header_value = HeaderValue::from_str(&value)
            .map_err(|e| SplunkError::Auth(format!("invalid header: {}", e)))?;
        headers.insert(AUTHORIZATION, header_value);
        Ok(headers)
    }

    /// キャッシュ済みの session key が無ければ `/services/auth/login` を叩く。
    async fn login_if_needed(&self, username: &str, password: &str) -> Result<String> {
        {
            let guard = self.cached_session.read().await;
            if let Some(ref sk) = *guard {
                return Ok(sk.clone());
            }
        }
        let mut guard = self.cached_session.write().await;
        if let Some(ref sk) = *guard {
            return Ok(sk.clone());
        }

        let url = format!("{}/services/auth/login?output_mode=json", self.base_url);
        let resp = self
            .http
            .post(&url)
            .form(&[("username", username), ("password", password)])
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let mut body = resp.text().await.unwrap_or_default();
            body.truncate(200);
            return Err(SplunkError::Auth(format!("{}: {}", status, body)));
        }
        let parsed: LoginResponse = resp.json().await?;
        *guard = Some(parsed.session_key.clone());
        Ok(parsed.session_key)
    }

    /// キャッシュされた session を破棄する。401 応答時などに使用する。
    pub async fn invalidate(&self) {
        let mut guard = self.cached_session.write().await;
        *guard = None;
    }
}

/// `/services/auth/login` のレスポンス body。
///
/// `Debug` は派生しない。`session_key` は長期有効な秘密値なので
/// 派生 Debug 経由の `{:?}` でも絶対に展開させたくない。
#[derive(Deserialize)]
struct LoginResponse {
    #[serde(rename = "sessionKey")]
    session_key: String,
}

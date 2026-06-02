use crate::config::credential_store::{default_store, CredentialStore, KEY_OAUTH_SESSION};
use crate::config::{AuthMethod, Credentials, OAuthAuto};
use crate::error::{Result, SplunkError};
use crate::oauth::{self, OAuthSession};
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
    /// OAuth (`auth login`) セッションの自動更新状態。OAuth セッション由来の
    /// `BearerToken` のときだけ `Some`。Splunk token 失効時に再交換／refresh する。
    oauth: Option<Arc<RwLock<OAuthState>>>,
}

/// 自動更新が扱う可変状態。`session` は失効時に `ensure_fresh_session` で差し替わる。
struct OAuthState {
    config: crate::oauth::OAuthConfig,
    base_url: String,
    session: OAuthSession,
    /// 更新後の書き戻し先。テストではメモリストアを注入する。
    store: Arc<dyn CredentialStore>,
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
            .field("oauth", &self.oauth.as_ref().map(|_| "<refresh-enabled>"))
            .finish()
    }
}

impl Authorizer {
    pub fn new(creds: &Credentials, http: reqwest::Client) -> Self {
        Self::new_with_store(creds, http, default_store().map(Arc::from))
    }

    /// store を注入できる版。テストから使う。
    /// `store` が `None` の場合、OAuth 自動更新は無効（refresh の書き戻し先が無いため）。
    pub fn new_with_store(
        creds: &Credentials,
        http: reqwest::Client,
        store: Option<Arc<dyn CredentialStore>>,
    ) -> Self {
        let oauth = build_oauth_state(creds, store).map(|s| Arc::new(RwLock::new(s)));
        Self {
            base_url: creds.base_url.clone(),
            method: creds.auth.clone(),
            cached_session: Arc::new(RwLock::new(None)),
            http,
            oauth,
        }
    }

    /// 現在の認証方式に対応する Authorization ヘッダを構築する。
    pub async fn auth_header(&self) -> Result<HeaderMap> {
        let value = match &self.method {
            AuthMethod::BearerToken(t) => {
                // OAuth 自動更新が有効なら、失効間近のとき refresh してから組む。
                // 無効（手動 Bearer）の場合は固定値 `t` をそのまま使う。
                let token = self.bearer_token(t).await?;
                format!("Bearer {}", token)
            }
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

    /// Bearer に載せる Splunk token を返す。OAuth 自動更新が有効で Splunk token が
    /// 失効間近なら、Entra access での再交換（必要なら Entra refresh）を行い、
    /// store に書き戻してから返す。OAuth 無効（手動 Bearer）の場合は固定値を返す。
    async fn bearer_token(&self, fixed: &str) -> Result<String> {
        let Some(state_lock) = &self.oauth else {
            return Ok(fixed.to_string());
        };

        // Splunk token が失効していなければそのまま返す（read ロックのみ）。
        {
            let state = state_lock.read().await;
            if !state.session.splunk_expired(oauth::now_unix()) {
                return Ok(state.session.splunk_token.clone());
            }
        }

        // 失効間近。write ロックで二重チェックしてから更新する。
        let mut state = state_lock.write().await;
        if !state.session.splunk_expired(oauth::now_unix()) {
            return Ok(state.session.splunk_token.clone());
        }

        match oauth::ensure_fresh_session(
            &state.session,
            &state.config,
            &state.base_url,
            &self.http,
        )
        .await
        {
            Ok(refreshed) => {
                if refreshed.changed {
                    // 更新を store に 1 エントリ（JSON）で書き戻す。書き戻し失敗は
                    // 警告にとどめ、取得した token は今回のプロセスで使えるようにする。
                    persist_session(state.store.as_ref(), &refreshed.session);
                    state.session = refreshed.session;
                }
                Ok(state.session.splunk_token.clone())
            }
            Err(e) => {
                // Entra refresh までは成功して Splunk 交換で失敗した場合、前進した
                // 中間セッションを保存しておく（次回の再 refresh の無駄と、
                // refresh token ローテーション時の喪失を防ぐ）。
                if let Some(partial) = e.partial {
                    persist_session(state.store.as_ref(), &partial);
                    state.session = partial;
                }
                Err(e.error)
            }
        }
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
            let body = resp.text().await.unwrap_or_default();
            let body = crate::util::truncate_chars(&body, 200);
            return Err(SplunkError::Auth(format!("{}: {}", status, body)));
        }
        let parsed: LoginResponse = resp.json().await?;
        *guard = Some(parsed.session_key.clone());
        Ok(parsed.session_key)
    }

    /// キャッシュされた認証状態を失効扱いにする。401 応答時などに使用する。
    ///
    /// - Basic 認証: キャッシュ済み session key を破棄し、次回 `/services/auth/login`
    ///   を再実行させる。
    /// - OAuth: Splunk token の expiry を「過去」に倒し、次回 `bearer_token` で
    ///   必ず再交換させる。Splunk がクロックずれ等で期限前に token を失効させた
    ///   （サーバ側失効）場合に、`splunk_expired` が false のまま再交換されず
    ///   401 を繰り返す事態を防ぐ。
    pub async fn invalidate(&self) {
        {
            let mut guard = self.cached_session.write().await;
            *guard = None;
        }
        if let Some(state_lock) = &self.oauth {
            let mut state = state_lock.write().await;
            // 過去（0）に倒す。次の bearer_token が必ず失効と判定する。
            state.session.splunk_expires_at = 0;
        }
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

/// `Credentials` から OAuth 自動更新の初期状態を組む。
///
/// 次のすべてを満たすときのみ `Some`:
///   - `auth` が `BearerToken`
///   - `oauth` が `Some`（OAuth セッション / 設定 / base_url が揃う）
///   - `store` が `Some`（更新結果の書き戻し先がある）
fn build_oauth_state(
    creds: &Credentials,
    store: Option<Arc<dyn CredentialStore>>,
) -> Option<OAuthState> {
    if !matches!(creds.auth, AuthMethod::BearerToken(_)) {
        return None;
    }
    let OAuthAuto {
        session,
        config,
        base_url,
    } = creds.oauth.clone()?;
    let store = store?;
    Some(OAuthState {
        config,
        base_url,
        session,
        store,
    })
}

/// 更新後の OAuth セッションを store に 1 エントリ（JSON）で書き戻す。
/// 失敗は標準エラーへの警告にとどめる（今回取得した token は使えるため）。
fn persist_session(store: &dyn CredentialStore, session: &OAuthSession) {
    match session.to_json() {
        Ok(json) => {
            if let Err(e) = store.set(KEY_OAUTH_SESSION, &json) {
                eprintln!("warning: failed to persist refreshed oauth session: {}", e);
            }
        }
        Err(e) => eprintln!("warning: failed to serialize oauth session: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::credential_store::test_support::MemoryStore;
    use crate::config::{Credentials, OAuthAuto};
    use crate::oauth::{OAuthConfig, OAuthSession};

    fn oauth_config() -> OAuthConfig {
        OAuthConfig {
            tenant_id: "tenant".into(),
            client_id: "client".into(),
            scope: "api://client/user_impersonation".into(),
        }
    }

    fn make_session(splunk_exp: u64) -> OAuthSession {
        OAuthSession {
            splunk_token: "SPLUNK".into(),
            splunk_expires_at: splunk_exp,
            entra_access_token: "ENTRA".into(),
            entra_expires_at: splunk_exp,
            refresh_token: Some("RT".into()),
        }
    }

    fn oauth_creds(splunk_exp: u64, with_oauth: bool) -> Credentials {
        let session = make_session(splunk_exp);
        Credentials {
            base_url: "https://example.splunkcloud.com:8089".into(),
            auth: AuthMethod::BearerToken(session.splunk_token.clone()),
            default_app: "search".into(),
            default_user: "nobody".into(),
            oauth: with_oauth.then(|| OAuthAuto {
                session,
                config: oauth_config(),
                base_url: "https://example.splunkcloud.com:8089".into(),
            }),
        }
    }

    #[test]
    fn build_oauth_state_requires_oauth_context() {
        let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
        // oauth なし → None
        assert!(build_oauth_state(&oauth_creds(0, false), Some(store.clone())).is_none());
        // oauth あり → Some
        assert!(build_oauth_state(&oauth_creds(123, true), Some(store)).is_some());
    }

    #[test]
    fn build_oauth_state_none_without_store() {
        assert!(build_oauth_state(&oauth_creds(123, true), None).is_none());
    }

    #[test]
    fn build_oauth_state_none_for_session_key() {
        let creds = Credentials {
            base_url: "https://e:8089".into(),
            auth: AuthMethod::SessionKey("SK".into()),
            default_app: "search".into(),
            default_user: "nobody".into(),
            oauth: None,
        };
        let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
        assert!(build_oauth_state(&creds, Some(store)).is_none());
    }

    #[tokio::test]
    async fn bearer_token_returns_current_when_valid() {
        let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
        let creds = oauth_creds(oauth::now_unix() + 3600, true);
        let auth = Authorizer::new_with_store(&creds, reqwest::Client::new(), Some(store));
        // Splunk token が失効していないので更新せず現在値を返す
        let tok = auth.bearer_token("SPLUNK").await.unwrap();
        assert_eq!(tok, "SPLUNK");
    }

    #[tokio::test]
    async fn bearer_token_fixed_when_no_oauth() {
        // OAuth 無効（手動 Bearer）の場合は固定値をそのまま使う
        let creds = oauth_creds(0, false);
        let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
        let auth = Authorizer::new_with_store(&creds, reqwest::Client::new(), Some(store));
        let tok = auth.bearer_token("FIXED").await.unwrap();
        assert_eq!(tok, "FIXED");
    }

    #[test]
    fn persist_session_writes_json_entry() {
        let store = MemoryStore::new();
        persist_session(&store, &make_session(9999));
        let raw = store.get(KEY_OAUTH_SESSION).unwrap().unwrap();
        let back = OAuthSession::from_json(&raw).unwrap();
        assert_eq!(back.splunk_token, "SPLUNK");
        assert_eq!(back.splunk_expires_at, 9999);
        assert_eq!(back.refresh_token.as_deref(), Some("RT"));
    }
}

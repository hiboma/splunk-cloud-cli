use crate::config::credential_store::{
    default_store, CredentialStore, KEY_REFRESH_TOKEN, KEY_TOKEN, KEY_TOKEN_EXPIRY,
};
use crate::config::{AuthMethod, Credentials, OAuthRefreshContext};
use crate::error::{Result, SplunkError};
use crate::oauth;
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
    /// OAuth (Device Code) token の自動更新状態。`BearerToken` かつ
    /// store に refresh token がある場合のみ `Some`。失効間近で refresh する。
    oauth: Option<Arc<RwLock<OAuthState>>>,
}

/// 自動更新が扱う可変状態。`access_token` は失効時に refresh で差し替わる。
struct OAuthState {
    config: crate::oauth::OAuthConfig,
    access_token: String,
    refresh_token: String,
    expires_at: u64,
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

    /// Bearer に載せる access token を返す。OAuth 自動更新が有効で失効間近なら
    /// refresh して store に書き戻してから返す。それ以外は引数の固定値を返す。
    async fn bearer_token(&self, fixed: &str) -> Result<String> {
        let Some(state_lock) = &self.oauth else {
            return Ok(fixed.to_string());
        };

        // 失効していなければ現在の access token をそのまま返す（read ロックのみ）。
        {
            let state = state_lock.read().await;
            if !is_expired(state.expires_at) {
                return Ok(state.access_token.clone());
            }
        }

        // 失効間近。write ロックで二重チェックしてから refresh する。
        let mut state = state_lock.write().await;
        if !is_expired(state.expires_at) {
            return Ok(state.access_token.clone());
        }

        let new = oauth::refresh(&state.config, &self.http, &state.refresh_token).await?;
        // 更新を store に書き戻す。書き戻し失敗は警告にとどめ、取得した
        // token は今回のプロセスでは使えるようにする（次回起動で再 refresh）。
        persist_refresh(state.store.as_ref(), &new);

        state.access_token = new.access_token.clone();
        state.expires_at = new.expires_at;
        if let Some(rt) = new.refresh_token {
            state.refresh_token = rt;
        }
        Ok(state.access_token.clone())
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

/// 安全マージン込みで失効しているか判定する。`oauth::EXPIRY_SKEW_SECS` を共有する。
fn is_expired(expires_at: u64) -> bool {
    oauth::now_unix().saturating_add(oauth::EXPIRY_SKEW_SECS) >= expires_at
}

/// `Credentials` から OAuth 自動更新の初期状態を組む。
///
/// 次のすべてを満たすときのみ `Some`:
///   - `auth` が `BearerToken`（現在の access token を初期値に使う）
///   - `oauth_refresh` が `Some`（refresh token / expiry / OAuth 設定が揃う）
///   - `store` が `Some`（refresh 結果の書き戻し先がある）
fn build_oauth_state(
    creds: &Credentials,
    store: Option<Arc<dyn CredentialStore>>,
) -> Option<OAuthState> {
    let AuthMethod::BearerToken(access_token) = &creds.auth else {
        return None;
    };
    let OAuthRefreshContext {
        config,
        refresh_token,
        expires_at,
    } = creds.oauth_refresh.clone()?;
    let store = store?;
    Some(OAuthState {
        config,
        access_token: access_token.clone(),
        refresh_token,
        expires_at,
        store,
    })
}

/// refresh で得た新しい token / expiry / refresh token を store に書き戻す。
/// 失敗は標準エラーへの警告にとどめる（今回取得した token は使えるため）。
fn persist_refresh(store: &dyn CredentialStore, new: &oauth::TokenSet) {
    if let Err(e) = store.set(KEY_TOKEN, &new.access_token) {
        eprintln!("warning: failed to persist refreshed access token: {}", e);
    }
    if let Err(e) = store.set(KEY_TOKEN_EXPIRY, &new.expires_at.to_string()) {
        eprintln!("warning: failed to persist refreshed token expiry: {}", e);
    }
    if let Some(rt) = &new.refresh_token {
        if let Err(e) = store.set(KEY_REFRESH_TOKEN, rt) {
            eprintln!("warning: failed to persist rotated refresh token: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::credential_store::test_support::MemoryStore;
    use crate::config::Credentials;
    use crate::oauth::{OAuthConfig, TokenSet};

    fn oauth_config() -> OAuthConfig {
        OAuthConfig {
            tenant_id: "tenant".into(),
            client_id: "client".into(),
            scope: "api://client/user_impersonation".into(),
        }
    }

    fn bearer_creds(expires_at: u64, with_refresh: bool) -> Credentials {
        Credentials {
            base_url: "https://example.splunkcloud.com:8089".into(),
            auth: AuthMethod::BearerToken("AT".into()),
            default_app: "search".into(),
            default_user: "nobody".into(),
            oauth_refresh: with_refresh.then(|| OAuthRefreshContext {
                config: oauth_config(),
                refresh_token: "RT".into(),
                expires_at,
            }),
        }
    }

    #[test]
    fn is_expired_respects_skew() {
        let now = oauth::now_unix();
        // 余裕たっぷり先 → not expired
        assert!(!is_expired(now + 3600));
        // マージン（60 秒）内 → expired 扱い
        assert!(is_expired(now + 30));
        // 過去 → expired
        assert!(is_expired(now.saturating_sub(10)));
    }

    #[test]
    fn build_oauth_state_requires_refresh_context() {
        let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
        // oauth_refresh なし → None
        assert!(build_oauth_state(&bearer_creds(0, false), Some(store.clone())).is_none());
        // oauth_refresh あり → Some
        assert!(build_oauth_state(&bearer_creds(123, true), Some(store)).is_some());
    }

    #[test]
    fn build_oauth_state_none_without_store() {
        // store が無ければ書き戻せないので無効化
        assert!(build_oauth_state(&bearer_creds(123, true), None).is_none());
    }

    #[test]
    fn build_oauth_state_none_for_session_key() {
        let creds = Credentials {
            base_url: "https://e:8089".into(),
            auth: AuthMethod::SessionKey("SK".into()),
            default_app: "search".into(),
            default_user: "nobody".into(),
            oauth_refresh: None,
        };
        let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
        assert!(build_oauth_state(&creds, Some(store)).is_none());
    }

    #[tokio::test]
    async fn bearer_token_returns_current_when_valid() {
        let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
        let creds = bearer_creds(oauth::now_unix() + 3600, true);
        let auth = Authorizer::new_with_store(&creds, reqwest::Client::new(), Some(store));
        // 失効していないので refresh せず現在の AT を返す
        let tok = auth.bearer_token("AT").await.unwrap();
        assert_eq!(tok, "AT");
    }

    #[tokio::test]
    async fn bearer_token_fixed_when_no_oauth() {
        // OAuth 無効（手動 Bearer）の場合は固定値をそのまま使う
        let creds = bearer_creds(0, false);
        let store: Arc<dyn CredentialStore> = Arc::new(MemoryStore::new());
        let auth = Authorizer::new_with_store(&creds, reqwest::Client::new(), Some(store));
        let tok = auth.bearer_token("FIXED").await.unwrap();
        assert_eq!(tok, "FIXED");
    }

    #[test]
    fn persist_refresh_writes_store() {
        let store = MemoryStore::new();
        let new = TokenSet {
            access_token: "NEW".into(),
            refresh_token: Some("NEWR".into()),
            expires_at: 9999,
        };
        persist_refresh(&store, &new);
        assert_eq!(store.get(KEY_TOKEN).unwrap().as_deref(), Some("NEW"));
        assert_eq!(
            store.get(KEY_TOKEN_EXPIRY).unwrap().as_deref(),
            Some("9999")
        );
        assert_eq!(
            store.get(KEY_REFRESH_TOKEN).unwrap().as_deref(),
            Some("NEWR")
        );
    }

    #[test]
    fn persist_refresh_keeps_old_refresh_when_not_rotated() {
        let store = MemoryStore::new();
        store.set(KEY_REFRESH_TOKEN, "OLD").unwrap();
        let new = TokenSet {
            access_token: "NEW".into(),
            refresh_token: None,
            expires_at: 1,
        };
        persist_refresh(&store, &new);
        // ローテーションが無ければ既存の refresh token を維持する
        assert_eq!(
            store.get(KEY_REFRESH_TOKEN).unwrap().as_deref(),
            Some("OLD")
        );
    }
}

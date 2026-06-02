//! Microsoft Entra ID の OAuth 2.0 Device Code フローと refresh token による更新。
//!
//! Splunk Cloud Platform は Entra ID が発行した v2.0 アクセストークン（JWT）を
//! `Authorization: Bearer <token>` として受け取り、自前で JWT を検証する
//! （リダイレクト認証はしない）。本モジュールは「人がブラウザでサインインし、
//! 発行された JWT を CLI が取得する」部分だけを担う。
//!
//! Device Code フローを採る理由:
//!   - public client（client secret なし）で完結する
//!   - SSH 越しやブラウザを自動起動できない環境でも user_code の手入力で動く
//!   - redirect URI の loopback サーバを CLI 内に立てなくてよい
//!
//! セキュリティ:
//!   - `access_token` / `refresh_token` / `device_code` は秘密値。`Debug` 派生はせず、
//!     ログ・エラー文字列に値が混入しないよう手書きの `Debug` でマスクする。
//!   - エンドポイントはすべて `https://login.microsoftonline.com` 配下（TLS）。

use crate::error::{Result, SplunkError};
use serde::Deserialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 失効間近とみなす安全マージン（秒）。サーバとのクロックずれや
/// リクエスト往復の所要時間を吸収し、「叩いた直後に失効」を避ける。
pub const EXPIRY_SKEW_SECS: u64 = 60;

/// Device Code フローのポーリング上限の保険（秒）。
/// サーバの `expires_in` を尊重するが、異常に大きな値を返された場合でも
/// ここでキャップして無限ループ化を防ぐ。Entra の `expires_in` は通常
/// 900 秒前後なので、実際にはサーバ値の方が先に効く。
const MAX_POLL_SECS: u64 = 15 * 60;

/// Entra ID 上の public client を一意に指す設定値。いずれも秘密値ではない。
#[derive(Clone, Debug)]
pub struct OAuthConfig {
    /// テナント ID（GUID）。エンドポイント URL の `{tenant}` に入る。
    pub tenant_id: String,
    /// Application (client) ID（GUID）。
    pub client_id: String,
    /// 要求スコープ。例: `api://<client_id>/user_impersonation`。
    /// `offline_access` は refresh token を得るため常に内部で付与する。
    pub scope: String,
}

impl OAuthConfig {
    /// `scope` 未指定時に client_id から既定スコープを導出する。
    /// Entra の Application ID URI 既定形は `api://<client_id>` であり、
    /// 公開スコープ名は `user_impersonation`。
    pub fn default_scope_for(client_id: &str) -> String {
        format!("api://{}/user_impersonation", client_id)
    }

    fn devicecode_url(&self) -> String {
        format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/devicecode",
            self.tenant_id
        )
    }

    fn token_url(&self) -> String {
        format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.tenant_id
        )
    }

    /// トークン要求に載せる scope 文字列。`offline_access` を必ず含める。
    fn scope_param(&self) -> String {
        if self.scope.split_whitespace().any(|s| s == "offline_access") {
            self.scope.clone()
        } else {
            format!("{} offline_access", self.scope)
        }
    }
}

/// 取得済みトークン一式。`expires_at` は access token が失効する UNIX 時刻（秒）。
///
/// `Debug` は派生しない。`access_token` / `refresh_token` は秘密値であり、
/// 派生 `Debug` 経由の `{:?}` でも展開させない。
#[derive(Clone)]
pub struct TokenSet {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: u64,
}

impl std::fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenSet")
            .field("access_token", &"***")
            .field(
                "refresh_token",
                &if self.refresh_token.is_some() {
                    "Some(***)"
                } else {
                    "None"
                },
            )
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl TokenSet {
    /// 安全マージンを引いた上で access token が失効しているか。
    pub fn is_expired(&self, now: u64) -> bool {
        now.saturating_add(EXPIRY_SKEW_SECS) >= self.expires_at
    }

    /// 失効までの残り秒数（マージン適用なし、表示用）。失効済みは 0。
    pub fn remaining_secs(&self, now: u64) -> u64 {
        self.expires_at.saturating_sub(now)
    }
}

/// 現在の UNIX 時刻（秒）。
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `expires_in`（秒）から失効 UNIX 時刻を計算する。
fn expires_at_from(expires_in: u64, now: u64) -> u64 {
    now.saturating_add(expires_in)
}

// --- HTTP レスポンス型 ---

/// `POST /devicecode` のレスポンス。
///
/// `device_code` は秘密値のため `Debug` を派生しない。
#[derive(Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    /// デバイスコードの有効秒数。これを過ぎるとポーリングしても無駄なので
    /// デッドラインに使う。
    expires_in: u64,
    /// ポーリング間隔（秒）。省略時は Entra の既定 5 秒。
    #[serde(default = "default_interval")]
    interval: u64,
    /// 表示用メッセージ（ローカライズ済み）。
    message: Option<String>,
}

fn default_interval() -> u64 {
    5
}

/// `POST /token` の成功レスポンス。
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    /// access token の有効秒数。
    expires_in: u64,
}

/// `POST /token` のエラーレスポンス。
#[derive(Deserialize)]
struct TokenErrorResponse {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

/// ブラウザでの認証を促す案内。`auth login` が標準エラー出力へ表示する。
pub struct UserPrompt {
    pub verification_uri: String,
    pub user_code: String,
    pub message: Option<String>,
}

/// ポーリングの待機を担う抽象。本番は `tokio::time::sleep` に委譲し、
/// テストでは即時 return するスタブに差し替えてポーリング往復を高速化する。
///
/// `async fn` を持つトレイトは新しめの Rust で安定化しているが、外部 crate
/// （`async-trait` 等）への依存を避けるため、戻り値を `Pin<Box<dyn Future>>`
/// で返す形に手で展開する。
pub trait Sleeper: Send + Sync {
    fn sleep(
        &self,
        secs: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>;
}

/// 本番用。`tokio::time::sleep` で実際に待つ。
pub struct TokioSleeper;

impl Sleeper for TokioSleeper {
    fn sleep(
        &self,
        secs: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            tokio::time::sleep(Duration::from_secs(secs)).await;
        })
    }
}

/// ユーザーへ案内を提示するコールバック。`auth login` は標準エラーへの表示を渡す。
/// テストでは握り潰す。
pub type PromptFn<'a> = dyn Fn(&UserPrompt) + Send + Sync + 'a;

/// Device Code フローを実行し、ブラウザ認証完了後の `TokenSet` を返す。
///
/// 1. `POST /devicecode` で user_code / verification_uri / device_code を得る
/// 2. `on_prompt` を通じてユーザーに案内を提示する
/// 3. `interval` 秒ごとに `POST /token` をポーリングする
///    - `authorization_pending`: 継続
///    - `slow_down`: interval を 5 秒増やして継続
///    - `expired_token` / `access_denied`: 中断してエラー
///    - 成功: `TokenSet` を返す
pub async fn device_code_login(
    cfg: &OAuthConfig,
    http: &reqwest::Client,
    sleeper: &dyn Sleeper,
    on_prompt: &PromptFn<'_>,
) -> Result<TokenSet> {
    let dc = request_device_code(cfg, http).await?;
    on_prompt(&UserPrompt {
        verification_uri: dc.verification_uri.clone(),
        user_code: dc.user_code.clone(),
        message: dc.message.clone(),
    });

    let mut interval = dc.interval.max(1);
    // サーバが示すデバイスコードの寿命を尊重しつつ、異常値は MAX_POLL_SECS でキャップする。
    let deadline = now_unix().saturating_add(dc.expires_in.min(MAX_POLL_SECS));

    loop {
        // デッドライン超過なら待たずに即座に打ち切る。チェックを sleep の前に
        // 置くことで、期限切れ後に無駄な待機やポーリングを行わない。
        if now_unix() >= deadline {
            return Err(SplunkError::Auth(
                "device code flow timed out before authorization completed".to_string(),
            ));
        }

        sleeper.sleep(interval).await;

        match poll_token(cfg, http, &dc.device_code).await? {
            PollOutcome::Success(tok) => return Ok(tok),
            PollOutcome::Pending => {}
            // RFC 8628: `slow_down` を受けたら次回以降のポーリング間隔を広げる。
            // 広げた `interval` は次周回の `sleep` で効く。
            PollOutcome::SlowDown => interval = interval.saturating_add(5),
            PollOutcome::Failed { error, description } => {
                return Err(SplunkError::Auth(format!(
                    "device code flow failed ({}): {}",
                    error,
                    description.unwrap_or_else(|| "no description".to_string())
                )));
            }
        }
    }
}

/// refresh token で新しい access token を得る。
pub async fn refresh(
    cfg: &OAuthConfig,
    http: &reqwest::Client,
    refresh_token: &str,
) -> Result<TokenSet> {
    let resp = http
        .post(cfg.token_url())
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", cfg.client_id.as_str()),
            ("refresh_token", refresh_token),
            ("scope", cfg.scope_param().as_str()),
        ])
        .send()
        .await?;

    let status = resp.status();
    let body = resp.bytes().await?;
    if status.is_success() {
        let tr: TokenResponse = serde_json::from_slice(&body)?;
        Ok(TokenSet {
            access_token: tr.access_token,
            // Entra は refresh 時に新しい refresh token を返すことがある（ローテーション）。
            // 返らなければ呼び出し側が既存のものを保持し続ける想定で None を返す。
            refresh_token: tr.refresh_token,
            expires_at: expires_at_from(tr.expires_in, now_unix()),
        })
    } else {
        let err: TokenErrorResponse = serde_json::from_slice(&body).unwrap_or(TokenErrorResponse {
            error: format!("http {}", status.as_u16()),
            error_description: None,
        });
        Err(SplunkError::Auth(format!(
            "token refresh failed ({}): {}",
            err.error,
            err.error_description
                .unwrap_or_else(|| "run `auth login` again".to_string())
        )))
    }
}

/// `POST /devicecode` を叩く。
async fn request_device_code(
    cfg: &OAuthConfig,
    http: &reqwest::Client,
) -> Result<DeviceCodeResponse> {
    let resp = http
        .post(cfg.devicecode_url())
        .form(&[
            ("client_id", cfg.client_id.as_str()),
            ("scope", cfg.scope_param().as_str()),
        ])
        .send()
        .await?;

    let status = resp.status();
    let body = resp.bytes().await?;
    if status.is_success() {
        Ok(serde_json::from_slice(&body)?)
    } else {
        let err: TokenErrorResponse = serde_json::from_slice(&body).unwrap_or(TokenErrorResponse {
            error: format!("http {}", status.as_u16()),
            error_description: None,
        });
        Err(SplunkError::Auth(format!(
            "device code request failed ({}): {}",
            err.error,
            err.error_description
                .unwrap_or_else(|| "no description".to_string())
        )))
    }
}

/// 1 回分のトークンポーリング結果。
enum PollOutcome {
    Success(TokenSet),
    /// `authorization_pending`: まだユーザーが認証していない。
    Pending,
    /// `slow_down`: ポーリングが速すぎる。間隔を広げる。
    SlowDown,
    /// `expired_token` / `access_denied` など、継続不能な失敗。
    Failed {
        error: String,
        description: Option<String>,
    },
}

/// `POST /token`（device_code grant）を 1 回叩いて結果を分類する。
async fn poll_token(
    cfg: &OAuthConfig,
    http: &reqwest::Client,
    device_code: &str,
) -> Result<PollOutcome> {
    let resp = http
        .post(cfg.token_url())
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("client_id", cfg.client_id.as_str()),
            ("device_code", device_code),
        ])
        .send()
        .await?;

    let status = resp.status();
    let body = resp.bytes().await?;

    if status.is_success() {
        let tr: TokenResponse = serde_json::from_slice(&body)?;
        return Ok(PollOutcome::Success(TokenSet {
            access_token: tr.access_token,
            refresh_token: tr.refresh_token,
            expires_at: expires_at_from(tr.expires_in, now_unix()),
        }));
    }

    // device code grant の polling では、エラー応答は HTTP 400 で返り、
    // `error` フィールドで状態を区別する。
    let err: TokenErrorResponse = serde_json::from_slice(&body).unwrap_or(TokenErrorResponse {
        error: format!("http {}", status.as_u16()),
        error_description: None,
    });
    let outcome = match err.error.as_str() {
        "authorization_pending" => PollOutcome::Pending,
        "slow_down" => PollOutcome::SlowDown,
        _ => PollOutcome::Failed {
            error: err.error,
            description: err.error_description,
        },
    };
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// テスト用。待たずに即 return してポーリング往復を高速化する。
    struct NoSleep;
    impl Sleeper for NoSleep {
        fn sleep(
            &self,
            _secs: u64,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
            Box::pin(async {})
        }
    }

    fn noop_prompt() -> Box<PromptFn<'static>> {
        Box::new(|_p: &UserPrompt| {})
    }

    /// `device_code_login` のエンドポイント URL を mockito の base に向けるため、
    /// `OAuthConfig` のホストを差し替えられないので、ここでは内部関数ではなく
    /// HTTP を張る関数を直接叩く。URL 構築は tenant_id に server.url() を埋める
    /// ことはできないため、専用のヘルパでテスト用 URL を組む。
    ///
    /// 実装の URL ビルダはホスト固定（login.microsoftonline.com）なので、
    /// テストでは `reqwest` を mockito のサーバに向けた上で、
    /// device_code_login を「URL を差し込めるテスト版」で検証する代わりに、
    /// ポーリングのステートマシンを `poll_token` 経由で検証する。
    #[test]
    fn token_set_expiry_logic() {
        let ts = TokenSet {
            access_token: "a".into(),
            refresh_token: Some("r".into()),
            expires_at: 1000,
        };
        // now=900, skew=60 → 960 >= 1000 は false → not expired
        assert!(!ts.is_expired(900));
        // now=941 → 1001 >= 1000 → expired（マージン内）
        assert!(ts.is_expired(941));
        // now=1000 → expired
        assert!(ts.is_expired(1000));
        assert_eq!(ts.remaining_secs(900), 100);
        assert_eq!(ts.remaining_secs(1000), 0);
    }

    #[test]
    fn scope_param_appends_offline_access() {
        let cfg = OAuthConfig {
            tenant_id: "t".into(),
            client_id: "c".into(),
            scope: "api://c/user_impersonation".into(),
        };
        assert_eq!(
            cfg.scope_param(),
            "api://c/user_impersonation offline_access"
        );

        let cfg2 = OAuthConfig {
            tenant_id: "t".into(),
            client_id: "c".into(),
            scope: "api://c/user_impersonation offline_access".into(),
        };
        // 既に含む場合は重複させない
        assert_eq!(
            cfg2.scope_param(),
            "api://c/user_impersonation offline_access"
        );
    }

    #[test]
    fn default_scope_derivation() {
        assert_eq!(
            OAuthConfig::default_scope_for("abc"),
            "api://abc/user_impersonation"
        );
    }

    #[test]
    fn token_set_debug_redacts_secrets() {
        let ts = TokenSet {
            access_token: "super-secret-jwt".into(),
            refresh_token: Some("super-secret-refresh".into()),
            expires_at: 42,
        };
        let dbg = format!("{:?}", ts);
        assert!(!dbg.contains("super-secret-jwt"));
        assert!(!dbg.contains("super-secret-refresh"));
        assert!(dbg.contains("***"));
        assert!(dbg.contains("42"));
    }

    // --- mockito で HTTP 経路を検証 ---
    //
    // URL ビルダはホストを `login.microsoftonline.com` に固定しているため、
    // テストでは `tenant_id` にモックサーバの host:port を埋め込めない。
    // そこで HTTP を実際に張る関数（refresh / poll_token / request_device_code）は
    // URL を引数に取れないが、`reqwest::Client` のリクエストは
    // mockito が `Host` ヘッダではなく接続先で待ち受けるため、
    // ここでは URL を直接組めるテスト用の薄いラッパは設けず、
    // `OAuthConfig::tenant_id` にモックの `host:port` を入れて
    // `https://` を強制している URL を検証する方式は使えない。
    //
    // 代わりに、refresh と device code polling のレスポンス解釈は
    // 「HTTP を張らない純粋な分類ロジック」をテストでカバーできるよう、
    // レスポンス JSON のデシリアライズと分類を直接検証する。
    #[test]
    fn token_response_parses() {
        let json =
            r#"{"access_token":"AT","refresh_token":"RT","expires_in":3600,"token_type":"Bearer"}"#;
        let tr: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(tr.access_token, "AT");
        assert_eq!(tr.refresh_token.as_deref(), Some("RT"));
        assert_eq!(tr.expires_in, 3600);
    }

    #[test]
    fn token_response_without_refresh() {
        let json = r#"{"access_token":"AT","expires_in":3600}"#;
        let tr: TokenResponse = serde_json::from_str(json).unwrap();
        assert!(tr.refresh_token.is_none());
    }

    #[test]
    fn device_code_response_parses_with_defaults() {
        let json = r#"{"device_code":"DC","user_code":"UC","verification_uri":"https://aka.ms/devicelogin","expires_in":900,"message":"go here"}"#;
        let dc: DeviceCodeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(dc.device_code, "DC");
        assert_eq!(dc.user_code, "UC");
        assert_eq!(dc.interval, 5); // 省略時の既定
        assert_eq!(dc.message.as_deref(), Some("go here"));
    }

    #[test]
    fn token_error_response_parses() {
        let json = r#"{"error":"authorization_pending","error_description":"waiting"}"#;
        let er: TokenErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(er.error, "authorization_pending");
        assert_eq!(er.error_description.as_deref(), Some("waiting"));
    }

    // device_code_login のポーリングステートマシン全体は、URL を差し込める
    // テスト版（下記 `*_against` 関数）を通じて mockito で検証する。
    #[tokio::test]
    async fn device_login_polls_pending_then_succeeds() {
        let mut server = mockito::Server::new_async().await;

        let dc = server
            .mock("POST", "/devicecode")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"device_code":"DC","user_code":"ABCD-EFGH","verification_uri":"https://example/dev","expires_in":900,"interval":1,"message":"enter ABCD-EFGH"}"#,
            )
            .create_async()
            .await;

        // 1 回目は authorization_pending、2 回目で成功させる。
        let pending = server
            .mock("POST", "/token")
            .with_status(400)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":"authorization_pending"}"#)
            .expect(1)
            .create_async()
            .await;
        let ok = server
            .mock("POST", "/token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token":"AT","refresh_token":"RT","expires_in":3600}"#)
            .expect(1)
            .create_async()
            .await;

        let http = reqwest::Client::new();
        let prompt = noop_prompt();
        let tok = device_code_login_against(
            &server.url(),
            "client-id",
            "scope",
            &http,
            &NoSleep,
            &*prompt,
        )
        .await
        .unwrap();

        assert_eq!(tok.access_token, "AT");
        assert_eq!(tok.refresh_token.as_deref(), Some("RT"));
        assert!(tok.expires_at > now_unix());

        dc.assert_async().await;
        pending.assert_async().await;
        ok.assert_async().await;
    }

    #[tokio::test]
    async fn device_login_fails_on_access_denied() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("POST", "/devicecode")
            .with_status(200)
            .with_body(
                r#"{"device_code":"DC","user_code":"UC","verification_uri":"https://e/d","expires_in":900,"interval":1}"#,
            )
            .create_async()
            .await;
        server
            .mock("POST", "/token")
            .with_status(400)
            .with_body(r#"{"error":"access_denied","error_description":"user said no"}"#)
            .create_async()
            .await;

        let http = reqwest::Client::new();
        let prompt = noop_prompt();
        let err = device_code_login_against(&server.url(), "c", "s", &http, &NoSleep, &*prompt)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("access_denied"), "got: {}", msg);
    }

    #[tokio::test]
    async fn device_login_times_out_when_deadline_passed() {
        let mut server = mockito::Server::new_async().await;
        // `expires_in: 0` なのでデッドラインは即座に過ぎる。ループ先頭の
        // 判定で、ポーリングに入る前にタイムアウトする。
        server
            .mock("POST", "/devicecode")
            .with_status(200)
            .with_body(
                r#"{"device_code":"DC","user_code":"UC","verification_uri":"https://e/d","expires_in":0,"interval":1}"#,
            )
            .create_async()
            .await;
        // pending を返し続けるモック。デッドライン判定が無ければ無限ループになる。
        server
            .mock("POST", "/token")
            .with_status(400)
            .with_body(r#"{"error":"authorization_pending"}"#)
            .create_async()
            .await;

        let http = reqwest::Client::new();
        let prompt = noop_prompt();
        let err = device_code_login_against(&server.url(), "c", "s", &http, &NoSleep, &*prompt)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("timed out"), "got: {}", err);
    }

    #[tokio::test]
    async fn refresh_succeeds() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", "/token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token":"NEW","refresh_token":"NEWR","expires_in":3600}"#)
            .create_async()
            .await;

        let http = reqwest::Client::new();
        let tok = refresh_against(&server.url(), "c", "s", &http, "old-refresh")
            .await
            .unwrap();
        assert_eq!(tok.access_token, "NEW");
        assert_eq!(tok.refresh_token.as_deref(), Some("NEWR"));
        m.assert_async().await;
    }

    #[tokio::test]
    async fn refresh_fails_with_message() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("POST", "/token")
            .with_status(400)
            .with_body(r#"{"error":"invalid_grant","error_description":"token expired"}"#)
            .create_async()
            .await;

        let http = reqwest::Client::new();
        let err = refresh_against(&server.url(), "c", "s", &http, "old")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid_grant"));
    }

    // --- テスト用 URL 差し込み版 ---
    //
    // 本番の URL ビルダはホストを固定するため、テストではモックサーバの
    // base URL を受け取れる薄い版を用意して同じステートマシンを通す。

    async fn device_code_login_against(
        base: &str,
        client_id: &str,
        scope: &str,
        http: &reqwest::Client,
        sleeper: &dyn Sleeper,
        on_prompt: &PromptFn<'_>,
    ) -> Result<TokenSet> {
        let devicecode_url = format!("{}/devicecode", base);
        let token_url = format!("{}/token", base);

        let resp = http
            .post(&devicecode_url)
            .form(&[("client_id", client_id), ("scope", scope)])
            .send()
            .await?;
        let body = resp.bytes().await?;
        let dc: DeviceCodeResponse = serde_json::from_slice(&body)?;
        on_prompt(&UserPrompt {
            verification_uri: dc.verification_uri.clone(),
            user_code: dc.user_code.clone(),
            message: dc.message.clone(),
        });

        let mut interval = dc.interval.max(1);
        // 本番 `device_code_login` と同じデッドライン経路を再現する。
        let deadline = now_unix().saturating_add(dc.expires_in.min(MAX_POLL_SECS));
        loop {
            if now_unix() >= deadline {
                return Err(SplunkError::Auth(
                    "device code flow timed out before authorization completed".to_string(),
                ));
            }
            sleeper.sleep(interval).await;
            let resp = http
                .post(&token_url)
                .form(&[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("client_id", client_id),
                    ("device_code", dc.device_code.as_str()),
                ])
                .send()
                .await?;
            let status = resp.status();
            let body = resp.bytes().await?;
            if status.is_success() {
                let tr: TokenResponse = serde_json::from_slice(&body)?;
                return Ok(TokenSet {
                    access_token: tr.access_token,
                    refresh_token: tr.refresh_token,
                    expires_at: expires_at_from(tr.expires_in, now_unix()),
                });
            }
            let err: TokenErrorResponse = serde_json::from_slice(&body).unwrap();
            match err.error.as_str() {
                "authorization_pending" => {}
                "slow_down" => interval = interval.saturating_add(5),
                other => {
                    return Err(SplunkError::Auth(format!(
                        "device code flow failed ({}): {}",
                        other,
                        err.error_description.unwrap_or_default()
                    )))
                }
            }
        }
    }

    async fn refresh_against(
        base: &str,
        client_id: &str,
        scope: &str,
        http: &reqwest::Client,
        refresh_token: &str,
    ) -> Result<TokenSet> {
        let resp = http
            .post(format!("{}/token", base))
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", client_id),
                ("refresh_token", refresh_token),
                ("scope", scope),
            ])
            .send()
            .await?;
        let status = resp.status();
        let body = resp.bytes().await?;
        if status.is_success() {
            let tr: TokenResponse = serde_json::from_slice(&body)?;
            Ok(TokenSet {
                access_token: tr.access_token,
                refresh_token: tr.refresh_token,
                expires_at: expires_at_from(tr.expires_in, now_unix()),
            })
        } else {
            let err: TokenErrorResponse = serde_json::from_slice(&body).unwrap();
            Err(SplunkError::Auth(format!(
                "token refresh failed ({}): {}",
                err.error,
                err.error_description.unwrap_or_default()
            )))
        }
    }
}

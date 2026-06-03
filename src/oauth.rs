//! Microsoft Entra ID の OAuth 2.0 Authorization Code + PKCE フローと
//! refresh token による更新。
//!
//! Splunk Cloud Platform は Entra ID が発行した v2.0 アクセストークン（JWT）を
//! `Authorization: Bearer <token>` として受け取り、自前で JWT を検証する
//! （リダイレクト認証はしない）。本モジュールは「人がブラウザでサインインし、
//! 発行された JWT を CLI が取得する」部分だけを担う。
//!
//! Authorization Code + PKCE フローを採る理由:
//!   - public client（client secret なし）で、RFC 8252（ネイティブアプリの
//!     OAuth）に沿った推奨フロー。認可はブラウザ内で完結する。
//!   - PKCE（RFC 7636）により、認可コードを横取りされても code_verifier 無しでは
//!     トークン交換できない。
//!   - 認可レスポンスは loopback（`127.0.0.1`）の redirect URI で受けるため、
//!     利用者がコードを別経路から入力させられる device code phishing を構造的に
//!     避けられる（macOS / Windows のブラウザを開ける環境を前提とする）。
//!
//! セキュリティ:
//!   - `access_token` / `refresh_token` / `code_verifier` / 認可コードは秘密値。
//!     `Debug` 派生はせず、ログ・エラー文字列に値が混入しないよう手書きの `Debug`
//!     でマスクする。
//!   - `state` を `code_verifier` と紐づけ、認可レスポンスの `state` を
//!     定数時間比較で検証して CSRF / レスポンス取り違えを防ぐ。
//!   - loopback サーバは `127.0.0.1`（ループバック）のみで待ち受け、1 リクエスト
//!     処理したら即座に閉じる。
//!   - Entra のエンドポイントはすべて `https://login.microsoftonline.com` 配下（TLS）。

use crate::error::{Result, SplunkError};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// 失効間近とみなす安全マージン（秒）。サーバとのクロックずれや
/// リクエスト往復の所要時間を吸収し、「叩いた直後に失効」を避ける。
pub const EXPIRY_SKEW_SECS: u64 = 60;

/// loopback redirect URI の待ち受けポート（固定）。Entra ID のアプリ登録に
/// `http://127.0.0.1:49873/callback` を「モバイルアプリとデスクトップ
/// アプリケーション」のリダイレクト URI として登録しておく必要がある。
///
/// 固定にする理由: Entra はリダイレクト URI を完全一致で検証するため、毎回
/// 別ポートを使うとアプリ登録が追従できない。ポートは一般的な開発用ポートや
/// entraws（6432）と衝突しにくい値を選んでいる。
pub const REDIRECT_PORT: u16 = 49873;

/// ブラウザでの認証完了を待つ上限（秒）。これを過ぎたら loopback サーバを畳んで
/// エラーにする。利用者が放置したまま CLI がハングし続けるのを防ぐ。
const AUTH_WAIT_SECS: u64 = 5 * 60;

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

    fn authorize_url(&self) -> String {
        format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize",
            self.tenant_id
        )
    }

    fn token_url(&self) -> String {
        format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.tenant_id
        )
    }

    /// loopback redirect URI。Entra のアプリ登録と完全一致させる必要がある。
    pub fn redirect_uri() -> String {
        format!("http://127.0.0.1:{}/callback", REDIRECT_PORT)
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

/// サーバ由来のエラーテキスト（認可サーバの `error_description`、Splunk の
/// エラー本文など）を、端末・ログへ出す前に安全化する。
///
/// 1. JWT らしきトークン（`eyJ...` で始まる 3 セグメントの base64url 文字列）を
///    `***` に伏せる。Splunk 交換のエラー本文は `client_assertion`（Entra JWT、
///    秘密値）をエコーし得るため、断片混入を防ぐ。
/// 2. 制御文字（ANSI エスケープ等）を除去する。外部入力をそのまま端末へ出すと
///    エスケープシーケンス注入の余地があるため。
/// 3. 最後に文字数で切り詰める。
fn sanitize_server_text(s: &str, max: usize) -> String {
    let masked = mask_jwt_like(s);
    let cleaned: String = masked
        .chars()
        // 制御文字は落とす（改行・タブも端末出力では不要なので除く）。
        .filter(|c| !c.is_control())
        .collect();
    crate::util::truncate_chars(&cleaned, max)
}

/// `eyJ` で始まる JWT 様トークン（`header.payload.signature` の 3 セグメント、
/// 各セグメントは base64url 文字）を `***` に置き換える。
///
/// 空白で語に分け、各語の前後にある引用符・記号（`"` や `,` 等）は保ったまま、
/// 中央の JWT 部分だけを伏せる。JWT のセグメント区切りは `.` なので、`.` は
/// b64url 文字に含めて 1 語として扱い、`eyJ` 始まり・ドット 2 個で判定する。
fn mask_jwt_like(s: &str) -> String {
    // JWT 本体を構成しうる文字（base64url + セグメント区切りの `.`）。
    fn is_jwt_char(c: char) -> bool {
        c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'
    }
    let masked: Vec<String> = s
        .split_whitespace()
        .map(|word| {
            let core = word.trim_matches(|c: char| !is_jwt_char(c));
            if core.starts_with("eyJ") && core.matches('.').count() == 2 {
                // 前後の記号（引用符等）は残し、芯だけ伏せる。
                word.replacen(core, "***", 1)
            } else {
                word.to_string()
            }
        })
        .collect();
    masked.join(" ")
}

// --- PKCE ---

/// PKCE（RFC 7636）と CSRF 対策の一回限りパラメータ。
///
/// `code_verifier` は秘密値（これと認可コードが揃って初めてトークン交換できる）。
/// `Debug` は派生せず手書きでマスクする。`state` / `code_challenge` は秘密値ではない。
#[derive(Clone)]
pub struct PkceParams {
    /// CSRF 対策のランダム値。認可レスポンスの `state` と定数時間比較する。
    pub state: String,
    /// トークン交換に提示する検証値（秘密）。
    pub code_verifier: String,
    /// authorize 要求に載せる `SHA-256(code_verifier)` の base64url（no-pad）。
    pub code_challenge: String,
}

impl std::fmt::Debug for PkceParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PkceParams")
            .field("state", &self.state)
            .field("code_verifier", &"***")
            .field("code_challenge", &self.code_challenge)
            .finish()
    }
}

impl PkceParams {
    /// 暗号学的乱数から PKCE パラメータ一式を生成する。
    ///
    /// - `state`: 32 バイト → base64url（43 文字）
    /// - `code_verifier`: 64 バイト → base64url（86 文字。RFC 7636 の 43..=128 文字に収まる）
    /// - `code_challenge`: `BASE64URL(SHA256(code_verifier))`（S256 方式）
    pub fn generate() -> Self {
        let state = random_token(32);
        let code_verifier = random_token(64);
        let code_challenge = code_challenge_s256(&code_verifier);
        Self {
            state,
            code_verifier,
            code_challenge,
        }
    }
}

/// 暗号学的乱数 `n` バイトを base64url（no-pad）で文字列化する。
fn random_token(n: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; n];
    // OS の CSPRNG（getrandom）を直に引く。失敗しない実装。
    rand::rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// `code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))`（RFC 7636 S256）。
fn code_challenge_s256(code_verifier: &str) -> String {
    let digest = Sha256::digest(code_verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

// --- HTTP レスポンス型 ---

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

/// ブラウザで開く案内。`auth login` が標準エラー出力へ表示する。
pub struct UserPrompt {
    /// ブラウザで開く authorize URL（PKCE / state 込み）。
    pub authorize_url: String,
}

/// ユーザーへ案内を提示するコールバック。`auth login` は標準エラーへの表示と
/// ブラウザ起動を渡す。テストでは握り潰す。
pub type PromptFn<'a> = dyn Fn(&UserPrompt) + Send + Sync + 'a;

/// Authorization Code + PKCE フローを実行し、Entra の `TokenSet` を返す。
///
/// 1. PKCE（state / code_verifier / code_challenge）を生成する
/// 2. loopback（`127.0.0.1:REDIRECT_PORT`）に redirect 受け口を bind する
/// 3. `on_prompt` で authorize URL をユーザーに提示する（ブラウザ起動）
/// 4. ブラウザが redirect してくる認可レスポンス（`code` / `state`）を受ける
///    （favicon 取得などの無関係な接続は読み飛ばす）
/// 5. `state` を定数時間比較で検証し、`code` + `code_verifier` をトークンに交換する
///
/// `AUTH_WAIT_SECS` を過ぎても redirect が来なければタイムアウトする。
pub async fn authorization_code_login(
    cfg: &OAuthConfig,
    http: &reqwest::Client,
    on_prompt: &PromptFn<'_>,
) -> Result<TokenSet> {
    let pkce = PkceParams::generate();
    let redirect_uri = OAuthConfig::redirect_uri();

    // 先に bind する。ブラウザが redirect してくる前に受け口を用意し、
    // ポート競合（既に使用中）はここで早期に検出する。
    let listener = TcpListener::bind(("127.0.0.1", REDIRECT_PORT))
        .await
        .map_err(|e| {
            SplunkError::Auth(format!(
                "failed to bind loopback redirect server on 127.0.0.1:{} ({}). \
Another process may be using the port; close it and retry `auth login`.",
                REDIRECT_PORT, e
            ))
        })?;

    run_authorization_code_flow(
        &cfg.token_url(),
        cfg,
        &listener,
        &redirect_uri,
        &pkce,
        Duration::from_secs(AUTH_WAIT_SECS),
        http,
        on_prompt,
    )
    .await
}

/// `authorization_code_login` の本体。bind 済みの `listener`・token エンドポイント・
/// 待機時間を引数で受けることで、本番（固定ポート・ホスト固定・5 分待ち）と
/// テスト（任意ポート・mockito・短い待ち）で同じ制御フローを通す。
#[allow(clippy::too_many_arguments)]
async fn run_authorization_code_flow(
    token_endpoint: &str,
    cfg: &OAuthConfig,
    listener: &TcpListener,
    redirect_uri: &str,
    pkce: &PkceParams,
    wait: Duration,
    http: &reqwest::Client,
    on_prompt: &PromptFn<'_>,
) -> Result<TokenSet> {
    let authorize_url = build_authorize_url(cfg, redirect_uri, pkce);
    on_prompt(&UserPrompt {
        authorize_url: authorize_url.clone(),
    });

    // 認可 redirect を受ける。タイムアウト付き（放置時のハングを防ぐ）。
    let callback = tokio::time::timeout(wait, accept_callback(listener))
        .await
        .map_err(|_| {
            SplunkError::Auth("timed out waiting for the browser to complete sign-in".to_string())
        })??;

    // CSRF / レスポンス取り違え対策: state を定数時間比較する。
    if !constant_time_eq(callback.state.as_bytes(), pkce.state.as_bytes()) {
        return Err(SplunkError::Auth(
            "authorization response state did not match; aborting (possible CSRF)".to_string(),
        ));
    }

    // 認可サーバがエラーを返した場合（ユーザーが拒否した等）。
    // error / error_description は redirect クエリ由来の外部入力。端末へ出す前に
    // 制御文字（ANSI エスケープ等）を除き、長さを絞ってから埋める。
    if let Some(err) = callback.error {
        return Err(SplunkError::Auth(format!(
            "authorization failed ({}): {}",
            sanitize_server_text(&err, 80),
            sanitize_server_text(&callback.error_description.unwrap_or_default(), 200)
        )));
    }

    let code = callback.code.ok_or_else(|| {
        SplunkError::Auth("authorization response did not contain a code".to_string())
    })?;

    exchange_authorization_code_to(
        token_endpoint,
        cfg,
        http,
        &code,
        redirect_uri,
        &pkce.code_verifier,
    )
    .await
}

/// authorize エンドポイントの URL を組み立てる。
fn build_authorize_url(cfg: &OAuthConfig, redirect_uri: &str, pkce: &PkceParams) -> String {
    let scope = cfg.scope_param();
    let params = [
        ("client_id", cfg.client_id.as_str()),
        ("response_type", "code"),
        ("redirect_uri", redirect_uri),
        ("response_mode", "query"),
        ("scope", scope.as_str()),
        ("state", pkce.state.as_str()),
        ("code_challenge", pkce.code_challenge.as_str()),
        ("code_challenge_method", "S256"),
    ];
    let query: String = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{}?{}", cfg.authorize_url(), query)
}

/// authorization_code grant でトークンに交換する。token エンドポイントを引数で
/// 受けることで、本番（`run_authorization_code_flow` が `cfg.token_url()` を渡す）と
/// テスト（mockito の base URL）で同じ送信ロジックを通す。
async fn exchange_authorization_code_to(
    token_endpoint: &str,
    cfg: &OAuthConfig,
    http: &reqwest::Client,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> Result<TokenSet> {
    let resp = http
        .post(token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", cfg.client_id.as_str()),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", code_verifier),
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
            refresh_token: tr.refresh_token,
            expires_at: expires_at_from(tr.expires_in, now_unix()),
        })
    } else {
        let err: TokenErrorResponse = serde_json::from_slice(&body).unwrap_or(TokenErrorResponse {
            error: format!("http {}", status.as_u16()),
            error_description: None,
        });
        Err(SplunkError::Auth(format!(
            "authorization code exchange failed ({}): {}",
            err.error,
            err.error_description
                .unwrap_or_else(|| "no description".to_string())
        )))
    }
}

/// loopback redirect で受け取った認可レスポンスのクエリ。
struct CallbackParams {
    code: Option<String>,
    state: String,
    error: Option<String>,
    error_description: Option<String>,
}

/// loopback サーバで認可レスポンスを受け取り、`code` / `state` を取り出す。
///
/// HTTP/1.x のリクエストラインだけを読めば十分（`GET /callback?...&code=...&state=... HTTP/1.1`）。
/// ボディは読まない。認可レスポンス（`code` か `error` を含む）が来たら完了ページを
/// 返して返す。
///
/// ブラウザは `favicon.ico` の取得や接続のプリフェッチなど、認可 redirect 以外の
/// 接続を先に張ることがある。そうした「`code` も `error` も含まない」接続は完了
/// ページを出さずに軽い応答だけ返して読み飛ばし、本物の redirect を待ち続ける。
/// 全体は呼び出し側の `tokio::time::timeout` で時間上限が掛かるため、待ち続けても
/// ハングはしない。無関係接続が大量に来ても暴走しないよう回数の上限も設ける。
async fn accept_callback(listener: &TcpListener) -> Result<CallbackParams> {
    // 認可 redirect 以外の接続を読み飛ばす回数の上限（暴走防止の保険）。
    const MAX_STRAY_CONNECTIONS: usize = 50;

    for _ in 0..MAX_STRAY_CONNECTIONS {
        let (mut stream, _) = listener.accept().await.map_err(|e| {
            SplunkError::Auth(format!("failed to accept redirect connection: {}", e))
        })?;

        // 読み取り失敗（途中切断・サイズ超過など）は致命にせず、その接続を捨てて
        // 次の接続を待つ。本物の redirect が後から来る余地を残す。
        let Ok(target) = read_request_target(&mut stream).await else {
            continue;
        };
        let Some(params) = parse_callback_query(&target) else {
            continue;
        };

        // 認可 redirect とみなせる接続か（code か error を含む）。state だけの接続や
        // favicon 取得などは対象外として読み飛ばす。
        if params.code.is_none() && params.error.is_none() {
            // 認可 redirect ではない。軽い応答だけ返して閉じ、次の接続を待つ。
            write_stray_response(&mut stream).await;
            continue;
        }

        // 完了ページを返す。秘密値は一切含めない。
        let ok = params.error.is_none() && params.code.is_some();
        write_browser_response(&mut stream, ok).await;
        return Ok(params);
    }

    Err(SplunkError::Auth(
        "did not receive an authorization redirect on the loopback server".to_string(),
    ))
}

/// 認可 redirect 以外の接続（favicon 取得・プリフェッチ等）へ返す軽い応答。
/// 完了ページは出さない（本物の redirect が来ていないため）。
async fn write_stray_response(stream: &mut TcpStream) {
    let response = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
}

/// リクエストラインから request-target（`GET <target> HTTP/1.1` の `<target>`）を読む。
///
/// 先頭行だけ取れればよいので、CRLF まで（上限付きで）読む。ヘッダ・ボディは無視する。
async fn read_request_target(stream: &mut TcpStream) -> Result<String> {
    // リクエストラインは十分小さい。1 行分を上限付きで読み、行頭の "GET " と
    // 末尾の " HTTP/..." を剥がして target を得る。攻撃的に大きな入力は上限で打ち切る。
    const MAX: usize = 8 * 1024;
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    loop {
        let n = stream
            .read(&mut byte)
            .await
            .map_err(|e| SplunkError::Auth(format!("failed to read redirect request: {}", e)))?;
        if n == 0 {
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        if byte[0] != b'\r' {
            buf.push(byte[0]);
        }
        // リクエストラインが上限を超えたら、途中で切れた行を解釈せず明示的に弾く。
        // 正規のブラウザ redirect は十分小さく収まる。
        if buf.len() >= MAX {
            return Err(SplunkError::Auth(
                "redirect request line exceeded the size limit".to_string(),
            ));
        }
    }
    let line = String::from_utf8_lossy(&buf);
    // "GET /callback?... HTTP/1.1" → "/callback?..."
    let mut parts = line.split_whitespace();
    let _method = parts.next();
    let target = parts
        .next()
        .ok_or_else(|| SplunkError::Auth("malformed redirect request line".to_string()))?;
    Ok(target.to_string())
}

/// request-target（`/callback?code=...&state=...`）からコールバックパラメータを取り出す。
fn parse_callback_query(target: &str) -> Option<CallbackParams> {
    let query = target.split_once('?').map(|(_, q)| q).unwrap_or("");
    let mut code = None;
    let mut state = None;
    let mut error = None;
    let mut error_description = None;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let val = urlencoding::decode(v).map(|c| c.into_owned()).ok()?;
        match k {
            "code" => code = Some(val),
            "state" => state = Some(val),
            "error" => error = Some(val),
            "error_description" => error_description = Some(val),
            _ => {}
        }
    }
    Some(CallbackParams {
        code,
        // state が無い応答は検証で弾く。空文字を入れておく。
        state: state.unwrap_or_default(),
        error,
        error_description,
    })
}

/// ブラウザへ完了ページ（HTML）を返す。秘密値は含めない。
///
/// このページは「どこから開かれたのか」が分からないと利用者を不安にさせるため、
/// CLI 名（`splunk-cloud-cli`）と Splunk Cloud へのサインインである旨を明示する。
async fn write_browser_response(stream: &mut TcpStream, ok: bool) {
    // ブラウザのタブ／ウィンドウタイトル。どのツール由来か一目で分かるようにする。
    let title = if ok {
        "Signed in — splunk-cloud-cli"
    } else {
        "Sign-in failed — splunk-cloud-cli"
    };
    // ページ見出し。
    let heading = if ok { "Signed in" } else { "Sign-in failed" };
    let detail = if ok {
        "You are signed in to Splunk Cloud via Entra ID for the splunk-cloud-cli \
command-line tool. You can close this tab and return to the terminal."
    } else {
        "Sign-in to Splunk Cloud did not complete for the splunk-cloud-cli \
command-line tool. Return to the terminal for details."
    };
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{title}</title></head>\
<body style=\"font-family:system-ui,sans-serif;padding:2rem;max-width:40rem;margin:0 auto\">\
<p style=\"color:#555;font-size:0.85rem;letter-spacing:0.05em;text-transform:uppercase;margin:0\">splunk-cloud-cli</p>\
<h1 style=\"margin:0.25rem 0 0.5rem\">{heading}</h1><p>{detail}</p></body></html>",
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        html.len(),
        html
    );
    // 書き込み失敗は致命的でない（トークン交換はすでに進められる）。握り潰す。
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
}

/// 2 つのバイト列を定数時間で比較する。長さが違えば即 false だが、同じ長さの
/// 比較では早期 return せず全バイトを走査して、内容に依存した時間差を作らない。
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// refresh token で新しい access token を得る。
pub async fn refresh(
    cfg: &OAuthConfig,
    http: &reqwest::Client,
    refresh_token: &str,
) -> Result<TokenSet> {
    refresh_to(&cfg.token_url(), cfg, http, refresh_token).await
}

/// `refresh` の本体。token エンドポイントを引数で受けることで、本番（ホスト固定）と
/// テスト（mockito の base URL）で同じ送信ロジックを通す。
async fn refresh_to(
    token_endpoint: &str,
    cfg: &OAuthConfig,
    http: &reqwest::Client,
    refresh_token: &str,
) -> Result<TokenSet> {
    let resp = http
        .post(token_endpoint)
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

/// Splunk が交換で発行した access token。`token_type` は通常 "Bearer"。
///
/// `Debug` は派生しない。`access_token` は秘密値。
#[derive(Clone)]
pub struct SplunkToken {
    pub access_token: String,
    pub expires_at: u64,
}

impl std::fmt::Debug for SplunkToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SplunkToken")
            .field("access_token", &"***")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl SplunkToken {
    pub fn is_expired(&self, now: u64) -> bool {
        now.saturating_add(EXPIRY_SKEW_SECS) >= self.expires_at
    }
}

/// `POST /token` の交換レスポンス。
#[derive(Deserialize)]
struct SplunkTokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// `auth login` の OAuth セッション一式。credential store に 1 つの JSON
/// エントリ（`oauth_session`）として保存し、Keychain アクセスを 1 回にまとめる。
///
/// `Debug` / `Display` は実装しない。`splunk_token` / `entra_access_token` /
/// `refresh_token` は秘密値であり、`{:?}` 経由でも展開させない。
/// JSON シリアライズはストア保存専用に使う（ログ等には出さない）。
#[derive(Clone, Serialize, Deserialize)]
pub struct OAuthSession {
    /// REST API に Bearer で送る Splunk 発行トークン。
    pub splunk_token: String,
    /// Splunk token の失効 UNIX 時刻（秒）。
    pub splunk_expires_at: u64,
    /// Entra ID の access token（JWT）。Splunk token 再交換の client_assertion。
    pub entra_access_token: String,
    /// Entra access token の失効 UNIX 時刻（秒）。
    pub entra_expires_at: u64,
    /// Entra ID の refresh token。Entra access も失効したときの再取得に使う。
    /// 取得できなかった場合は None。
    pub refresh_token: Option<String>,
}

impl std::fmt::Debug for OAuthSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthSession")
            .field("splunk_token", &"***")
            .field("splunk_expires_at", &self.splunk_expires_at)
            .field("entra_access_token", &"***")
            .field("entra_expires_at", &self.entra_expires_at)
            .field(
                "refresh_token",
                &if self.refresh_token.is_some() {
                    "Some(***)"
                } else {
                    "None"
                },
            )
            .finish()
    }
}

impl OAuthSession {
    /// ログインで得た Entra トークンと交換後の Splunk トークンから組む。
    pub fn from_login(entra: &TokenSet, splunk: &SplunkToken) -> Self {
        Self {
            splunk_token: splunk.access_token.clone(),
            splunk_expires_at: splunk.expires_at,
            entra_access_token: entra.access_token.clone(),
            entra_expires_at: entra.expires_at,
            refresh_token: entra.refresh_token.clone(),
        }
    }

    /// JSON 文字列へ（ストア保存用）。
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(SplunkError::from)
    }

    /// JSON 文字列から復元（ストア読み出し用）。
    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(SplunkError::from)
    }

    /// Splunk token が（安全マージン込みで）失効しているか。
    pub fn splunk_expired(&self, now: u64) -> bool {
        now.saturating_add(EXPIRY_SKEW_SECS) >= self.splunk_expires_at
    }

    /// Entra access token が（安全マージン込みで）失効しているか。
    pub fn entra_expired(&self, now: u64) -> bool {
        now.saturating_add(EXPIRY_SKEW_SECS) >= self.entra_expires_at
    }
}

/// `ensure_fresh_session` の結果。
pub struct Refreshed {
    /// 更新後（または未更新ならそのまま）のセッション。
    pub session: OAuthSession,
    /// 入力から `session` が変化したか（変化したら store へ書き戻すべき）。
    pub changed: bool,
}

/// Splunk token を有効な状態にして返す。必要なら 3 段階で更新する。
///
/// 1. Splunk token が有効 → そのまま返す（`changed=false`）
/// 2. Splunk token 失効 & Entra access 有効 → Entra access で再交換
/// 3. Splunk token 失効 & Entra access も失効 & refresh token あり → Entra refresh → 新 Entra access で再交換
///
/// いずれも失敗、または refresh token が無ければエラー（再ログインを促す）。
///
/// 重要: Entra refresh に成功した後で Splunk 交換が失敗した場合でも、
/// refresh で得た新しい Entra access / refresh token はエラーに添えて返す
/// （`RefreshErr::partial`）。呼び出し側はそれを store に書き戻すことで、
/// 次回の再 refresh の無駄と（ローテーション時の）refresh token 喪失を防げる。
pub async fn ensure_fresh_session(
    session: &OAuthSession,
    cfg: &OAuthConfig,
    base_url: &str,
    http: &reqwest::Client,
) -> std::result::Result<Refreshed, RefreshErr> {
    let now = now_unix();
    if !session.splunk_expired(now) {
        return Ok(Refreshed {
            session: session.clone(),
            changed: false,
        });
    }

    let mut next = session.clone();
    // Entra を refresh したかどうか（交換失敗時に部分的前進を返すため記録）。
    let mut entra_refreshed = false;

    // Entra access が失効していれば refresh で更新する。
    if next.entra_expired(now) {
        let Some(rt) = next.refresh_token.clone() else {
            return Err(RefreshErr {
                error: SplunkError::Auth(
                    "Splunk token expired and no refresh token is stored. \
Run `auth login` again."
                        .to_string(),
                ),
                partial: None,
            });
        };
        let refreshed = match refresh(cfg, http, &rt).await {
            Ok(r) => r,
            Err(e) => {
                return Err(RefreshErr {
                    error: e,
                    partial: None,
                })
            }
        };
        next.entra_access_token = refreshed.access_token;
        next.entra_expires_at = refreshed.expires_at;
        // Entra が refresh token をローテーションしたら更新、しなければ既存を維持。
        if refreshed.refresh_token.is_some() {
            next.refresh_token = refreshed.refresh_token;
        }
        entra_refreshed = true;
    }

    // Entra access token を Splunk token に交換する。
    let splunk =
        match exchange_for_splunk_token(base_url, &cfg.client_id, http, &next.entra_access_token)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                // 交換は失敗したが、Entra を refresh して前進した場合は、その
                // 中間セッションをエラーに添えて返す（呼び出し側が保存できる）。
                return Err(RefreshErr {
                    error: e,
                    partial: entra_refreshed.then_some(next),
                });
            }
        };
    next.splunk_token = splunk.access_token;
    next.splunk_expires_at = splunk.expires_at;

    Ok(Refreshed {
        session: next,
        changed: true,
    })
}

/// `ensure_fresh_session` の失敗。`partial` には、エラーまでに前進した
/// 中間セッション（Entra refresh は成功したが Splunk 交換が失敗した等）を入れる。
/// 呼び出し側は `partial` を store に書き戻してから `error` を伝播してよい。
pub struct RefreshErr {
    pub error: SplunkError,
    pub partial: Option<OAuthSession>,
}

/// Entra ID の access token (JWT) を Splunk access token に交換する。
///
/// Splunk Cloud の OAuth 2.0 external application server は外部 IdP の JWT を
/// REST API で直接受理せず、まず `oauth2/v1/token` で「Splunk 発行トークン」へ
/// 交換する必要がある。交換は Client Credentials Grant + JWT client assertion
/// 方式で、Entra JWT を `client_assertion` として渡す（Authorization ヘッダは
/// 付けない。エンドポイントは client_assertion で認証する public endpoint）。
///
/// `base_url` は Splunk の接続先（例: `https://<stack>.splunkcloud.com:8089`）。
/// 交換エンドポイントは `/oauth2/v1/token`（`/services` プレフィックスなし）。
pub async fn exchange_for_splunk_token(
    base_url: &str,
    client_id: &str,
    http: &reqwest::Client,
    entra_jwt: &str,
) -> Result<SplunkToken> {
    let url = format!("{}/oauth2/v1/token", base_url.trim_end_matches('/'));
    let resp = http
        .post(&url)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("client_assertion", entra_jwt),
        ])
        .send()
        .await?;

    let status = resp.status();
    let body = resp.bytes().await?;
    if status.is_success() {
        let tr: SplunkTokenResponse = serde_json::from_slice(&body)?;
        Ok(SplunkToken {
            access_token: tr.access_token,
            // expires_in が無ければ控えめに 1 時間とみなす（Splunk の既定）。
            expires_at: expires_at_from(tr.expires_in.unwrap_or(3600), now_unix()),
        })
    } else {
        // エラー本文から Splunk のメッセージを短く抜き出す。
        // 交換リクエストは `client_assertion`（Entra JWT、秘密値）を送るため、
        // サーバが受信値をエコーする実装だとエラー本文に JWT 断片が混じり得る。
        // `sanitize_server_text` で JWT 様トークンを伏字にし、制御文字も除いてから出す。
        let msg = String::from_utf8_lossy(&body);
        let snippet = sanitize_server_text(&msg, 200);
        Err(SplunkError::Auth(format!(
            "Splunk token exchange failed (http {}): {}",
            status.as_u16(),
            snippet
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noop_prompt() -> Box<PromptFn<'static>> {
        Box::new(|_p: &UserPrompt| {})
    }

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

    // --- PKCE ---

    #[test]
    fn pkce_code_challenge_matches_rfc7636_example() {
        // RFC 7636 Appendix B のテストベクタ。
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = code_challenge_s256(verifier);
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn pkce_generate_produces_distinct_high_entropy_values() {
        let a = PkceParams::generate();
        let b = PkceParams::generate();
        // 毎回違う値（乱数）であること。
        assert_ne!(a.state, b.state);
        assert_ne!(a.code_verifier, b.code_verifier);
        // code_challenge は code_verifier から導出され、長さは 43（base64url no-pad の SHA-256）。
        assert_eq!(a.code_challenge.len(), 43);
        assert_eq!(a.code_challenge, code_challenge_s256(&a.code_verifier));
        // state は base64url no-pad の 32 バイト → 43 文字。
        assert_eq!(a.state.len(), 43);
    }

    #[test]
    fn pkce_debug_redacts_verifier() {
        let p = PkceParams {
            state: "the-state".into(),
            code_verifier: "super-secret-verifier".into(),
            code_challenge: "the-challenge".into(),
        };
        let dbg = format!("{:?}", p);
        assert!(!dbg.contains("super-secret-verifier"));
        assert!(dbg.contains("***"));
        // state / challenge は秘密値でないので出てよい。
        assert!(dbg.contains("the-state"));
        assert!(dbg.contains("the-challenge"));
    }

    #[test]
    fn constant_time_eq_behaves_like_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }

    // --- authorize URL ---

    #[test]
    fn authorize_url_contains_pkce_and_state() {
        let cfg = OAuthConfig {
            tenant_id: "tenant".into(),
            client_id: "client".into(),
            scope: "api://client/user_impersonation".into(),
        };
        let pkce = PkceParams {
            state: "STATE".into(),
            code_verifier: "VERIFIER".into(),
            code_challenge: "CHALLENGE".into(),
        };
        let url = build_authorize_url(&cfg, "http://127.0.0.1:49873/callback", &pkce);
        assert!(url.starts_with("https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize?"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=client"));
        assert!(url.contains("code_challenge=CHALLENGE"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("state=STATE"));
        // redirect_uri と scope は URL エンコードされる。
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A49873%2Fcallback"));
        assert!(url.contains("offline_access"));
    }

    #[test]
    fn redirect_uri_uses_fixed_loopback_port() {
        assert_eq!(
            OAuthConfig::redirect_uri(),
            format!("http://127.0.0.1:{}/callback", REDIRECT_PORT)
        );
    }

    // --- callback query パース ---

    #[test]
    fn parse_callback_query_extracts_code_and_state() {
        let p = parse_callback_query("/callback?code=AUTHCODE&state=STATEVAL").unwrap();
        assert_eq!(p.code.as_deref(), Some("AUTHCODE"));
        assert_eq!(p.state, "STATEVAL");
        assert!(p.error.is_none());
    }

    #[test]
    fn parse_callback_query_url_decodes() {
        // code は URL エンコードされて届くことがある。
        let p = parse_callback_query("/callback?code=a%2Fb%2Bc&state=s").unwrap();
        assert_eq!(p.code.as_deref(), Some("a/b+c"));
    }

    #[test]
    fn parse_callback_query_extracts_error() {
        let p = parse_callback_query(
            "/callback?error=access_denied&error_description=user%20said%20no&state=s",
        )
        .unwrap();
        assert_eq!(p.error.as_deref(), Some("access_denied"));
        assert_eq!(p.error_description.as_deref(), Some("user said no"));
        assert!(p.code.is_none());
    }

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
    fn token_error_response_parses() {
        let json = r#"{"error":"invalid_grant","error_description":"bad code"}"#;
        let er: TokenErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(er.error, "invalid_grant");
        assert_eq!(er.error_description.as_deref(), Some("bad code"));
    }

    // --- authorization_code 交換（mockito で本番ロジックを検証）---
    //
    // 本番の URL ビルダはホストを `login.microsoftonline.com` に固定するため、
    // テストでは token エンドポイントを引数で受ける本番内部関数
    // `exchange_authorization_code_to` / `refresh_to` を mockito の base URL へ
    // 向けて直接叩く。これにより、送信フォーム（特に `scope=...offline_access` の
    // 付与）が本番コードのまま検証される。

    fn test_cfg() -> OAuthConfig {
        OAuthConfig {
            tenant_id: "tenant".into(),
            client_id: "client".into(),
            scope: "api://client/user_impersonation".into(),
        }
    }

    #[tokio::test]
    async fn authorization_code_exchange_succeeds() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", "/token")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("grant_type".into(), "authorization_code".into()),
                mockito::Matcher::UrlEncoded("client_id".into(), "client".into()),
                mockito::Matcher::UrlEncoded("code".into(), "AUTHCODE".into()),
                mockito::Matcher::UrlEncoded("code_verifier".into(), "VERIFIER".into()),
                mockito::Matcher::UrlEncoded(
                    "redirect_uri".into(),
                    "http://127.0.0.1:49873/callback".into(),
                ),
                // 本番が `offline_access` を必ず付けることを検証する。
                mockito::Matcher::UrlEncoded(
                    "scope".into(),
                    "api://client/user_impersonation offline_access".into(),
                ),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token":"AT","refresh_token":"RT","expires_in":3600}"#)
            .create_async()
            .await;

        let http = reqwest::Client::new();
        let token_endpoint = format!("{}/token", server.url());
        let tok = exchange_authorization_code_to(
            &token_endpoint,
            &test_cfg(),
            &http,
            "AUTHCODE",
            "http://127.0.0.1:49873/callback",
            "VERIFIER",
        )
        .await
        .unwrap();
        assert_eq!(tok.access_token, "AT");
        assert_eq!(tok.refresh_token.as_deref(), Some("RT"));
        assert!(tok.expires_at > now_unix());
        m.assert_async().await;
    }

    #[tokio::test]
    async fn authorization_code_exchange_fails_with_message() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("POST", "/token")
            .with_status(400)
            .with_body(r#"{"error":"invalid_grant","error_description":"code already redeemed"}"#)
            .create_async()
            .await;

        let http = reqwest::Client::new();
        let token_endpoint = format!("{}/token", server.url());
        let err = exchange_authorization_code_to(
            &token_endpoint,
            &test_cfg(),
            &http,
            "AUTHCODE",
            "http://127.0.0.1:49873/callback",
            "VERIFIER",
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("invalid_grant"), "got: {}", err);
    }

    // --- refresh（mockito で本番ロジックを検証）---

    #[tokio::test]
    async fn refresh_succeeds() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", "/token")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("grant_type".into(), "refresh_token".into()),
                mockito::Matcher::UrlEncoded("client_id".into(), "client".into()),
                mockito::Matcher::UrlEncoded("refresh_token".into(), "old-refresh".into()),
                mockito::Matcher::UrlEncoded(
                    "scope".into(),
                    "api://client/user_impersonation offline_access".into(),
                ),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token":"NEW","refresh_token":"NEWR","expires_in":3600}"#)
            .create_async()
            .await;

        let http = reqwest::Client::new();
        let token_endpoint = format!("{}/token", server.url());
        let tok = refresh_to(&token_endpoint, &test_cfg(), &http, "old-refresh")
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
        let token_endpoint = format!("{}/token", server.url());
        let err = refresh_to(&token_endpoint, &test_cfg(), &http, "old")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid_grant"));
    }

    // --- loopback サーバ: 実際に bind して redirect を受け、code/state を取り出す ---

    #[tokio::test]
    async fn accept_callback_reads_code_and_state() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // 別タスクから「ブラウザの redirect」を模した HTTP リクエストを送る。
        let client = tokio::spawn(async move {
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(
                b"GET /callback?code=THECODE&state=THESTATE HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            )
            .await
            .unwrap();
            // サーバの完了 HTML を読み捨てる。
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf).await;
            buf
        });

        let params = accept_callback(&listener).await.unwrap();
        assert_eq!(params.code.as_deref(), Some("THECODE"));
        assert_eq!(params.state, "THESTATE");

        let resp = client.await.unwrap();
        let text = String::from_utf8_lossy(&resp);
        assert!(text.contains("200 OK"));
        // 完了ページに秘密値（code）が漏れていないこと。
        assert!(!text.contains("THECODE"));
        // 利用者が「どのツールから開かれたか」分かるよう CLI 名を明示していること。
        assert!(text.contains("splunk-cloud-cli"));
    }

    #[tokio::test]
    async fn authorization_code_login_rejects_state_mismatch() {
        // login 全体は authorize URL の組み立て後、ブラウザからの redirect を
        // 待つ。ここでは redirect 側が誤った state を返したとき弾くことを、
        // accept_callback + 比較ロジックの結線で確認する。
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(b"GET /callback?code=C&state=WRONG HTTP/1.1\r\n\r\n")
                .await
                .unwrap();
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf).await;
        });
        let params = accept_callback(&listener).await.unwrap();
        assert!(!constant_time_eq(params.state.as_bytes(), b"EXPECTED"));
        client.await.unwrap();
    }

    #[tokio::test]
    async fn accept_callback_skips_stray_connection_then_takes_redirect() {
        // favicon 取得など、認可 redirect 以外の接続が先に来ても読み飛ばし、
        // 後続の本物の redirect を受けることを確認する。
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // 1 本目: code も error も含まない無関係な接続（favicon 取得）。
        let stray = tokio::spawn(async move {
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(b"GET /favicon.ico HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                .await
                .unwrap();
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf).await;
            buf
        });
        // stray が先に accept されるよう、本物の redirect は少し遅らせて張る。
        let redirect = tokio::spawn(async move {
            // 1 本目が処理されるまでの猶予。tokio のタイマで待つ（実時間に依存しない）。
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(b"GET /callback?code=REALCODE&state=S HTTP/1.1\r\n\r\n")
                .await
                .unwrap();
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf).await;
            buf
        });

        let params = accept_callback(&listener).await.unwrap();
        assert_eq!(params.code.as_deref(), Some("REALCODE"));

        // stray には 204（完了ページなし）が返ること。
        let stray_resp = String::from_utf8_lossy(&stray.await.unwrap()).into_owned();
        assert!(stray_resp.contains("204"), "got: {}", stray_resp);
        assert!(!stray_resp.contains("Signed in"));
        // 本物の redirect には完了ページが返ること。
        let redirect_resp = String::from_utf8_lossy(&redirect.await.unwrap()).into_owned();
        assert!(redirect_resp.contains("200 OK"));
        assert!(redirect_resp.contains("splunk-cloud-cli"));
    }

    // --- サーバ由来テキストのサニタイズ ---

    #[test]
    fn sanitize_masks_jwt_like_tokens() {
        // header.payload.signature の 3 セグメント JWT を伏字にする。
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc-_DEF123";
        let input = format!("invalid assertion: {} rejected", jwt);
        let out = sanitize_server_text(&input, 200);
        assert!(!out.contains("eyJhbGciOiJIUzI1NiJ9"), "JWT leaked: {}", out);
        assert!(!out.contains(jwt), "JWT leaked: {}", out);
        assert!(out.contains("***"));
        // 周囲のテキストは保つ。
        assert!(out.contains("invalid assertion"));
        assert!(out.contains("rejected"));
    }

    #[test]
    fn sanitize_strips_control_characters() {
        // ANSI エスケープ等の制御文字を端末へ出さない。
        let input = "error\x1b[31m red \x07 bell\ndesc";
        let out = sanitize_server_text(input, 200);
        assert!(!out.contains('\x1b'));
        assert!(!out.contains('\x07'));
        assert!(!out.contains('\n'));
        assert!(out.contains("error"));
        assert!(out.contains("desc"));
    }

    #[test]
    fn sanitize_truncates_length() {
        let input = "a".repeat(500);
        let out = sanitize_server_text(&input, 200);
        assert_eq!(out.chars().count(), 200);
    }

    #[test]
    fn sanitize_keeps_ordinary_error_codes() {
        // 通常の OAuth エラーコード・説明はそのまま通す。
        let out = sanitize_server_text("invalid_grant: code already redeemed", 200);
        assert_eq!(out, "invalid_grant: code already redeemed");
    }

    // --- run_authorization_code_flow の結線テスト ---
    //
    // 任意ポートで bind した listener と mockito の token エンドポイント、短い
    // 待機時間を注入し、本体の各分岐（成功 / authorize エラー / code 欠落 /
    // state 不一致 / タイムアウト）を本番制御フローのまま検証する。

    fn fixed_pkce(state: &str) -> PkceParams {
        PkceParams {
            state: state.into(),
            code_verifier: "VERIFIER".into(),
            code_challenge: "CHALLENGE".into(),
        }
    }

    /// listener へ「ブラウザの redirect」を模した HTTP リクエストを 1 本送る。
    fn spawn_redirect(addr: std::net::SocketAddr, request_line: &'static str) {
        tokio::spawn(async move {
            let Ok(mut s) = TcpStream::connect(addr).await else {
                return;
            };
            let req = format!("{}\r\nHost: 127.0.0.1\r\n\r\n", request_line);
            let _ = s.write_all(req.as_bytes()).await;
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf).await;
        });
    }

    #[tokio::test]
    async fn flow_succeeds_end_to_end() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", "/token")
            .match_body(mockito::Matcher::UrlEncoded(
                "code".into(),
                "REALCODE".into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token":"AT","refresh_token":"RT","expires_in":3600}"#)
            .create_async()
            .await;

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        spawn_redirect(addr, "GET /callback?code=REALCODE&state=S HTTP/1.1");

        let http = reqwest::Client::new();
        let prompt = noop_prompt();
        let tok = run_authorization_code_flow(
            &format!("{}/token", server.url()),
            &test_cfg(),
            &listener,
            "http://127.0.0.1:49873/callback",
            &fixed_pkce("S"),
            Duration::from_secs(5),
            &http,
            &*prompt,
        )
        .await
        .unwrap();
        assert_eq!(tok.access_token, "AT");
        m.assert_async().await;
    }

    #[tokio::test]
    async fn flow_rejects_state_mismatch() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        // redirect は state=WRONG を返す。期待 state は "EXPECTED"。
        spawn_redirect(addr, "GET /callback?code=C&state=WRONG HTTP/1.1");

        let http = reqwest::Client::new();
        let prompt = noop_prompt();
        let err = run_authorization_code_flow(
            "http://unused.invalid/token",
            &test_cfg(),
            &listener,
            "http://127.0.0.1:49873/callback",
            &fixed_pkce("EXPECTED"),
            Duration::from_secs(5),
            &http,
            &*prompt,
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("state did not match"),
            "got: {}",
            err
        );
    }

    #[tokio::test]
    async fn flow_surfaces_authorize_error() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        spawn_redirect(
            addr,
            "GET /callback?error=access_denied&error_description=user%20declined&state=S HTTP/1.1",
        );

        let http = reqwest::Client::new();
        let prompt = noop_prompt();
        let err = run_authorization_code_flow(
            "http://unused.invalid/token",
            &test_cfg(),
            &listener,
            "http://127.0.0.1:49873/callback",
            &fixed_pkce("S"),
            Duration::from_secs(5),
            &http,
            &*prompt,
        )
        .await
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("access_denied"), "got: {}", msg);
        assert!(msg.contains("user declined"), "got: {}", msg);
    }

    #[tokio::test]
    async fn flow_surfaces_empty_error_param() {
        // `error=`（空文字）は authorize エラー分岐で拾われる。
        //
        // なお `code` も `error` も無い応答は `accept_callback` がスキップして
        // 待ち続けるため、本体の `code` 欠落分岐（"did not contain a code"）には
        // 通常到達しない。その分岐は防御的な保険として残してある。
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        spawn_redirect(addr, "GET /callback?error=&state=S HTTP/1.1");

        let http = reqwest::Client::new();
        let prompt = noop_prompt();
        let err = run_authorization_code_flow(
            "http://unused.invalid/token",
            &test_cfg(),
            &listener,
            "http://127.0.0.1:49873/callback",
            &fixed_pkce("S"),
            Duration::from_secs(5),
            &http,
            &*prompt,
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("authorization failed"),
            "got: {}",
            err
        );
    }

    #[tokio::test]
    async fn flow_times_out_without_redirect() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        // redirect を一切送らない。短い wait で即タイムアウトさせる。
        let http = reqwest::Client::new();
        let prompt = noop_prompt();
        let err = run_authorization_code_flow(
            "http://unused.invalid/token",
            &test_cfg(),
            &listener,
            "http://127.0.0.1:49873/callback",
            &fixed_pkce("S"),
            Duration::from_millis(50),
            &http,
            &*prompt,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("timed out"), "got: {}", err);
    }
}

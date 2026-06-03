use crate::cli::{AuthCmd, OutputFormat};
use crate::client::SplunkClient;
use crate::config::credential_store::{default_store, CredentialStore, KEY_OAUTH_SESSION};
use crate::config::{resolve_base_url, resolve_oauth_config, Settings};
use crate::error::{Result, SplunkError};
use crate::oauth::{self, OAuthSession, UserPrompt};
use crate::output::print_value;

/// Splunk への接続を必要とする `auth` サブコマンド（`whoami`）。
pub async fn run(cmd: &AuthCmd, client: &SplunkClient, format: OutputFormat) -> Result<()> {
    match cmd {
        AuthCmd::Whoami => {
            let value = client
                .get("/services/authentication/current-context", &[])
                .await?;
            print_value(&value, format)?;
        }
        // Login / Logout / Status は接続不要なため main 側で先に処理される。
        // ディスパッチの取りこぼしに気づけるよう明示的にエラーを返す。
        AuthCmd::Login | AuthCmd::Logout | AuthCmd::Status => {
            return Err(SplunkError::Config(
                "internal: login/logout/status must be handled before client setup".to_string(),
            ));
        }
    }
    Ok(())
}

/// Splunk への接続を必要としない `auth` サブコマンド（`login` / `logout` / `status`）。
/// 認証情報の取得・破棄・確認そのものが目的のため、client を組む前に処理する。
pub async fn run_oauth(cmd: &AuthCmd, settings: &Settings) -> Result<()> {
    let store = default_store().ok_or_else(|| {
        SplunkError::Config(
            "no OS credential store available on this platform. \
`auth login` requires macOS Keychain."
                .to_string(),
        )
    })?;

    match cmd {
        AuthCmd::Login => login(settings, store.as_ref()).await,
        AuthCmd::Logout => logout(store.as_ref()),
        AuthCmd::Status => status(store.as_ref()),
        AuthCmd::Whoami => Err(SplunkError::Config(
            "internal: whoami requires a Splunk client".to_string(),
        )),
    }
}

async fn login(settings: &Settings, store: &dyn CredentialStore) -> Result<()> {
    let cfg = resolve_oauth_config(settings)?;
    let http = reqwest::Client::builder()
        .user_agent(concat!("splunk-cloud-cli/", env!("CARGO_PKG_VERSION")))
        .build()?;

    // authorize URL の案内は標準エラーへ出す。標準出力は機械可読な結果のために
    // 空けておく。Authorization Code + PKCE では loopback サーバを先に bind した
    // 上でブラウザを開き、redirect で認可コードを受ける。
    let on_prompt = |p: &UserPrompt| {
        eprintln!();
        eprintln!("Opening your browser to sign in to Entra ID...");
        if open_in_browser(&p.authorize_url) {
            eprintln!("Opened the sign-in page.");
        } else {
            // ブラウザを開けない環境（権限・headless 等）向けの手動フォールバック。
            eprintln!("Could not open a browser. Open this URL manually:");
            eprintln!();
            eprintln!("    {}", p.authorize_url);
        }
        eprintln!();
        eprintln!("Waiting for you to complete sign-in in the browser...");
    };

    let entra = oauth::authorization_code_login(&cfg, &http, &on_prompt).await?;

    // Splunk Cloud は Entra JWT を REST API で直接受理しない。`oauth2/v1/token` で
    // Splunk 発行トークンへ交換する。
    let base_url = resolve_base_url(settings)?;
    let splunk =
        oauth::exchange_for_splunk_token(&base_url, &cfg.client_id, &http, &entra.access_token)
            .await?;

    // セッション一式（Splunk token / Entra access / refresh / 各 expiry）を
    // 1 つの JSON エントリにまとめて保存する。Keychain アクセスは 1 回。
    let session = OAuthSession::from_login(&entra, &splunk);
    save_session(store, &session)?;

    eprintln!("Signed in. Splunk access token stored in the OS credential store.");
    Ok(())
}

/// `authorize_url` を OS のデフォルトブラウザで開く。開けたら true。
///
/// shell を介さず `Command` で直接プログラムを起動し、URL は引数として渡す。
/// これにより、URL に shell メタ文字が含まれても解釈されない（インジェクション対策）。
/// 失敗しても呼び出し側は手動手順を表示済みなので、ここでは握り潰す。
fn open_in_browser(url: &str) -> bool {
    use std::process::{Command, Stdio};

    // 各 OS のブラウザ起動コマンド。引数として URL を渡す（shell 不使用）。
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = Command::new("open");
        c.arg(url);
        c
    };
    #[cfg(target_os = "windows")]
    let mut cmd = {
        // `cmd /c start "" <url>` 形式。空タイトルでウィンドウタイトル誤認を防ぐ。
        let mut c = Command::new("cmd");
        c.args(["/C", "start", "", url]);
        c
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut cmd = {
        let mut c = Command::new("xdg-open");
        c.arg(url);
        c
    };

    // 出力は端末を汚さないよう捨てる。
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    // status() は子プロセスの終了を待つ。open / xdg-open は即座に return する。
    matches!(cmd.status(), Ok(s) if s.success())
}

fn logout(store: &dyn CredentialStore) -> Result<()> {
    // OAuth セッションは 1 エントリ（JSON）に集約済み。それを消す。
    store
        .delete(KEY_OAUTH_SESSION)
        .map_err(|e| SplunkError::Config(format!("failed to delete oauth session: {}", e)))?;
    eprintln!("Signed out. Stored OAuth session removed.");
    Ok(())
}

fn status(store: &dyn CredentialStore) -> Result<()> {
    let Some(session) = load_session(store)? else {
        println!("No OAuth session stored. Run `auth login` to sign in.");
        return Ok(());
    };

    println!("Splunk access token: stored");
    println!(
        "Entra refresh token: {}",
        if session.refresh_token.is_some() {
            "stored"
        } else {
            "absent"
        }
    );

    let now = oauth::now_unix();
    let exp = session.splunk_expires_at;
    // 自動更新は `oauth::EXPIRY_SKEW_SECS` のマージン込みで失効判定する。
    // status の表示もこのマージンに合わせ、「valid 表示なのに次の
    // リクエストで refresh が走る」境界のずれをなくす。
    let refresh_threshold = exp.saturating_sub(oauth::EXPIRY_SKEW_SECS);
    if now >= exp {
        println!("Status: Splunk token expired ({} seconds ago)", now - exp);
        println!("It will be refreshed automatically on the next request.");
    } else if now >= refresh_threshold {
        println!("Status: Splunk token expiring within {}s", exp - now);
        println!("It will be refreshed automatically on the next request.");
    } else {
        let remaining = exp - now;
        println!(
            "Status: Splunk token valid for {} more seconds (~{} min)",
            remaining,
            remaining / 60
        );
    }
    Ok(())
}

/// OAuth セッションを credential store の単一 JSON エントリへ保存する。
fn save_session(store: &dyn CredentialStore, session: &OAuthSession) -> Result<()> {
    let json = session.to_json()?;
    store
        .set(KEY_OAUTH_SESSION, &json)
        .map_err(|e| SplunkError::Config(format!("failed to store oauth session: {}", e)))
}

/// credential store から OAuth セッションを読み出す。未保存なら None。
pub fn load_session(store: &dyn CredentialStore) -> Result<Option<OAuthSession>> {
    let raw = store
        .get(KEY_OAUTH_SESSION)
        .map_err(|e| SplunkError::Config(format!("failed to read oauth session: {}", e)))?;
    match raw {
        Some(s) if !s.is_empty() => Ok(Some(OAuthSession::from_json(&s)?)),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::credential_store::test_support::MemoryStore;

    fn session(refresh: Option<&str>, splunk_exp: u64) -> OAuthSession {
        OAuthSession {
            splunk_token: "SPLUNK".into(),
            splunk_expires_at: splunk_exp,
            entra_access_token: "ENTRA".into(),
            entra_expires_at: 11111,
            refresh_token: refresh.map(String::from),
        }
    }

    #[test]
    fn save_and_load_session_roundtrip() {
        let store = MemoryStore::new();
        save_session(&store, &session(Some("RT"), 22222)).unwrap();
        // 1 エントリ（JSON）にまとまっている。
        assert!(store.get(KEY_OAUTH_SESSION).unwrap().is_some());
        let loaded = load_session(&store).unwrap().unwrap();
        assert_eq!(loaded.splunk_token, "SPLUNK");
        assert_eq!(loaded.splunk_expires_at, 22222);
        assert_eq!(loaded.entra_access_token, "ENTRA");
        assert_eq!(loaded.refresh_token.as_deref(), Some("RT"));
    }

    #[test]
    fn load_session_none_when_empty() {
        let store = MemoryStore::new();
        assert!(load_session(&store).unwrap().is_none());
    }

    #[test]
    fn session_debug_redacts_secrets() {
        let dbg = format!("{:?}", session(Some("super-refresh"), 1));
        assert!(!dbg.contains("SPLUNK"));
        assert!(!dbg.contains("ENTRA"));
        assert!(!dbg.contains("super-refresh"));
        assert!(dbg.contains("***"));
    }

    #[test]
    fn logout_removes_session() {
        let store = MemoryStore::new();
        save_session(&store, &session(Some("RT"), 1)).unwrap();
        logout(&store).unwrap();
        assert!(store.get(KEY_OAUTH_SESSION).unwrap().is_none());
    }

    #[test]
    fn status_runs_without_session() {
        let store = MemoryStore::new();
        status(&store).unwrap();
    }

    #[test]
    fn status_runs_with_session() {
        let store = MemoryStore::new();
        save_session(&store, &session(Some("RT"), oauth::now_unix() + 3600)).unwrap();
        status(&store).unwrap();
    }
}

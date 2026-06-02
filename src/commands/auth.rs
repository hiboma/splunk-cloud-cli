use crate::cli::{AuthCmd, OutputFormat};
use crate::client::SplunkClient;
use crate::config::credential_store::{
    default_store, CredentialStore, KEY_REFRESH_TOKEN, KEY_TOKEN, KEY_TOKEN_EXPIRY,
};
use crate::config::{resolve_oauth_config, Settings};
use crate::error::{Result, SplunkError};
use crate::oauth::{self, TokenSet, TokioSleeper, UserPrompt};
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

    // ブラウザ案内は標準エラーへ出す。標準出力は機械可読な結果のために空けておく。
    let on_prompt = |p: &UserPrompt| {
        use std::io::IsTerminal;

        eprintln!();
        eprintln!("Your one-time code is:");
        eprintln!();
        eprintln!("    {}", emphasize_code(&p.user_code));
        eprintln!();

        // 対話端末では、まず code を確認させてから Enter でブラウザを開く。
        // 非対話（パイプ / CI）では Enter 待ちもブラウザ起動もせず、URL を
        // 表示してそのままポーリングに入る（スクリプトでブロックしない）。
        let interactive = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
        if interactive {
            eprint!("Press Enter to open the sign-in page in your browser (or open it yourself): ");
            wait_for_enter();
            if open_in_browser(&p.verification_uri) {
                eprintln!("Opened: {}", p.verification_uri);
            } else {
                eprintln!("Could not open a browser. Open this page manually:");
                eprintln!("    {}", p.verification_uri);
            }
        } else {
            eprintln!("To sign in, open this page in a browser and enter the code above:");
            eprintln!("    {}", p.verification_uri);
        }
        eprintln!();
        eprintln!("Waiting for you to complete sign-in in the browser...");
    };

    let token = oauth::device_code_login(&cfg, &http, &TokioSleeper, &on_prompt).await?;
    save_token(store, &token)?;

    eprintln!("Signed in. Access token stored in the OS credential store.");
    Ok(())
}

/// 標準入力から 1 行（Enter まで）を読み捨てる。対話端末でのみ呼ぶ。
/// EOF や読み取りエラーでもブロックせずに戻る。
fn wait_for_enter() {
    use std::io::BufRead;
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
}

/// user_code を目立たせる。stderr が端末なら ANSI の太字＋黄色で強調し、
/// パイプ・リダイレクト時（非 TTY）は装飾なしの素の文字列にする。
fn emphasize_code(code: &str) -> String {
    use std::io::IsTerminal;
    if std::io::stderr().is_terminal() {
        // 1 = bold, 33 = yellow。0 でリセット。
        format!("\x1b[1;33m{}\x1b[0m", code)
    } else {
        code.to_string()
    }
}

/// `verification_uri` を OS のデフォルトブラウザで開く。開けたら true。
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
    // delete は存在しないエントリでも Ok を返す実装なので、3 つとも無条件に消す。
    for key in [KEY_TOKEN, KEY_REFRESH_TOKEN, KEY_TOKEN_EXPIRY] {
        store
            .delete(key)
            .map_err(|e| SplunkError::Config(format!("failed to delete {}: {}", key, e)))?;
    }
    eprintln!("Signed out. Stored OAuth token, refresh token, and expiry removed.");
    Ok(())
}

fn status(store: &dyn CredentialStore) -> Result<()> {
    let has_token = read_opt(store, KEY_TOKEN)?.is_some();
    let has_refresh = read_opt(store, KEY_REFRESH_TOKEN)?.is_some();
    let expiry = read_opt(store, KEY_TOKEN_EXPIRY)?.and_then(|s| s.parse::<u64>().ok());

    if !has_token {
        println!("No OAuth access token stored. Run `auth login` to sign in.");
        return Ok(());
    }

    println!("Access token: stored");
    println!(
        "Refresh token: {}",
        if has_refresh { "stored" } else { "absent" }
    );
    match expiry {
        Some(exp) => {
            let now = oauth::now_unix();
            // 自動更新は `oauth::EXPIRY_SKEW_SECS` のマージン込みで失効判定する。
            // status の表示もこのマージンに合わせ、「valid 表示なのに次の
            // リクエストで refresh が走る」境界のずれをなくす。
            let refresh_threshold = exp.saturating_sub(oauth::EXPIRY_SKEW_SECS);
            if now >= exp {
                println!("Status: expired ({} seconds ago)", now - exp);
                if has_refresh {
                    println!("It will be refreshed automatically on the next request.");
                } else {
                    println!("No refresh token; run `auth login` again.");
                }
            } else if now >= refresh_threshold {
                // 失効はしていないがマージン内。次のリクエストで refresh される。
                println!("Status: expiring within {}s", exp - now);
                if has_refresh {
                    println!("It will be refreshed automatically on the next request.");
                } else {
                    println!("No refresh token; run `auth login` again soon.");
                }
            } else {
                let remaining = exp - now;
                println!(
                    "Status: valid for {} more seconds (~{} min)",
                    remaining,
                    remaining / 60
                );
            }
        }
        None => println!("Expiry: unknown (no expiry recorded)"),
    }
    Ok(())
}

/// 取得した `TokenSet` を credential store へ保存する。
///
/// access token は既存の `token` キーに保存することで、以後の REST 呼び出しが
/// 追加実装なしに Bearer 認証で動く。refresh token と失効時刻も併せて保存する。
fn save_token(store: &dyn CredentialStore, token: &TokenSet) -> Result<()> {
    store
        .set(KEY_TOKEN, &token.access_token)
        .map_err(|e| SplunkError::Config(format!("failed to store access token: {}", e)))?;
    store
        .set(KEY_TOKEN_EXPIRY, &token.expires_at.to_string())
        .map_err(|e| SplunkError::Config(format!("failed to store token expiry: {}", e)))?;
    match &token.refresh_token {
        Some(rt) => store
            .set(KEY_REFRESH_TOKEN, rt)
            .map_err(|e| SplunkError::Config(format!("failed to store refresh token: {}", e)))?,
        None => {
            // refresh token が返らなかった場合、古いものを残すと混乱するので消す。
            store.delete(KEY_REFRESH_TOKEN).map_err(|e| {
                SplunkError::Config(format!("failed to clear stale refresh token: {}", e))
            })?;
        }
    }
    Ok(())
}

fn read_opt(store: &dyn CredentialStore, key: &str) -> Result<Option<String>> {
    store
        .get(key)
        .map_err(|e| SplunkError::Config(format!("failed to read {}: {}", key, e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::credential_store::test_support::MemoryStore;

    fn token(expires_at: u64, refresh: Option<&str>) -> TokenSet {
        TokenSet {
            access_token: "AT".into(),
            refresh_token: refresh.map(String::from),
            expires_at,
        }
    }

    #[test]
    fn save_token_writes_all_three_keys() {
        let store = MemoryStore::new();
        save_token(&store, &token(12345, Some("RT"))).unwrap();
        assert_eq!(store.get(KEY_TOKEN).unwrap().as_deref(), Some("AT"));
        assert_eq!(store.get(KEY_REFRESH_TOKEN).unwrap().as_deref(), Some("RT"));
        assert_eq!(
            store.get(KEY_TOKEN_EXPIRY).unwrap().as_deref(),
            Some("12345")
        );
    }

    #[test]
    fn save_token_clears_stale_refresh_when_absent() {
        let store = MemoryStore::new();
        store.set(KEY_REFRESH_TOKEN, "OLD").unwrap();
        save_token(&store, &token(1, None)).unwrap();
        assert!(store.get(KEY_REFRESH_TOKEN).unwrap().is_none());
    }

    #[test]
    fn logout_removes_all_keys() {
        let store = MemoryStore::new();
        store.set(KEY_TOKEN, "AT").unwrap();
        store.set(KEY_REFRESH_TOKEN, "RT").unwrap();
        store.set(KEY_TOKEN_EXPIRY, "99").unwrap();
        logout(&store).unwrap();
        assert!(store.get(KEY_TOKEN).unwrap().is_none());
        assert!(store.get(KEY_REFRESH_TOKEN).unwrap().is_none());
        assert!(store.get(KEY_TOKEN_EXPIRY).unwrap().is_none());
    }

    #[test]
    fn status_runs_without_token() {
        let store = MemoryStore::new();
        // 標準出力に出すだけなので、エラーなく終わることを確認する。
        status(&store).unwrap();
    }

    #[test]
    fn status_runs_with_token() {
        let store = MemoryStore::new();
        store.set(KEY_TOKEN, "AT").unwrap();
        store.set(KEY_REFRESH_TOKEN, "RT").unwrap();
        store
            .set(KEY_TOKEN_EXPIRY, &(oauth::now_unix() + 3600).to_string())
            .unwrap();
        status(&store).unwrap();
    }
}

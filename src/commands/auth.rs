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
        if let Some(msg) = &p.message {
            eprintln!("{}", msg);
        } else {
            eprintln!(
                "To sign in, open {} and enter the code {}",
                p.verification_uri, p.user_code
            );
        }
        eprintln!("Waiting for you to complete sign-in in the browser...");
    };

    let token = oauth::device_code_login(&cfg, &http, &TokioSleeper, &on_prompt).await?;
    save_token(store, &token)?;

    eprintln!("Signed in. Access token stored in the OS credential store.");
    Ok(())
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
            if now >= exp {
                println!("Status: expired ({} seconds ago)", now - exp);
                if has_refresh {
                    println!("It will be refreshed automatically on the next request.");
                } else {
                    println!("No refresh token; run `auth login` again.");
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

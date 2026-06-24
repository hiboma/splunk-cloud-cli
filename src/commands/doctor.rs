//! `splunk-cloud-cli doctor` サブコマンドのハンドラ。
//!
//! jamf-cli の `doctor` に倣い、設定・資格情報・環境変数・接続性を一覧で診断する。
//! 設定の各値が「どこから解決されたか（config.toml / 環境変数 / OS credential
//! store）」を示すが、**秘密値そのものは決して印字しない**。出所と存在の有無だけを
//! 出す方針は `credentials status` と一貫させる。
//!
//! 診断ツールなので、接続失敗や資格情報の欠落で異常終了しない（既定 exit 0）。
//! `--strict` を付けたときだけ、問題があれば非ゼロで終了する。
//!
//! 出力先は標準出力。`-f json` などの format フラグは無視し、人間向けの固定
//! テキストを出す（jamf-cli の doctor と同じ扱い）。

use std::path::Path;
use std::time::Instant;

use crate::config::credential_store::{
    default_store, CredentialStore, StoreError, KEY_OAUTH_SESSION, KEY_PASSWORD, KEY_SESSION_KEY,
    KEY_TOKEN,
};
use crate::config::{config_search_paths, resolve_base_url, Settings};
use crate::error::Result;

/// 設定ファイルから解決されうる、秘密ではない環境変数のうち診断対象。
/// 値も併記する（秘密値ではないため）。
const NON_SECRET_ENV: &[&str] = &[
    "SPLUNK_BASE_URL",
    "SPLUNK_APP",
    "SPLUNK_USER",
    "SPLUNK_OAUTH_TENANT_ID",
    "SPLUNK_OAUTH_CLIENT_ID",
    "SPLUNK_OAUTH_SCOPE",
    "SPLUNK_DEBUG",
];

/// 秘密値を持つ環境変数のうち診断対象。値は印字せず set/unset のみ示す。
const SECRET_ENV: &[&str] = &["SPLUNK_TOKEN", "SPLUNK_SESSION_KEY", "SPLUNK_PASSWORD"];

/// `doctor` のエントリポイント。
///
/// `no_connect` が真なら接続プローブを省く。`strict` が真のとき、いずれかの
/// チェックが問題を報告したら非ゼロ終了するため `Ok(false)` を返す。
/// 呼び出し側（main）は戻り値を見て exit code を決める。
pub async fn run(no_connect: bool, strict: bool) -> Result<bool> {
    let settings = crate::config::load_settings().unwrap_or_default();
    let store = default_store();
    let store_ref = store.as_deref();

    let mut healthy = true;

    println!("splunk-cloud-cli {}", env!("CARGO_PKG_VERSION"));
    println!();

    print_config_block(&settings);
    println!();

    healthy &= print_credentials_block(&settings, store_ref);
    println!();

    print_environment_block();

    if !no_connect {
        println!();
        healthy &= print_connectivity_block(&settings).await;
    }

    if strict && !healthy {
        // strict 時は問題ありで非ゼロ終了させる。
        return Ok(false);
    }
    Ok(true)
}

/// CONFIG ブロック。設定ファイルの探索パスと、最初に見つかったファイルを示す。
fn print_config_block(_settings: &Settings) {
    println!("CONFIG");
    let paths = config_search_paths();
    let found = paths.iter().find(|p| p.exists());
    match found {
        Some(path) => {
            println!("  path:    {}", path.display());
            println!("  status:  present");
            print_permission_line(path);
        }
        None => {
            println!("  path:    (none found)");
            println!("  status:  absent");
            println!("  searched:");
            for p in &paths {
                println!("    - {}", p.display());
            }
        }
    }
}

/// 設定ファイルの permission を表示し、group/others から読める場合は警告を添える。
#[cfg(unix)]
fn print_permission_line(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            println!(
                "  perms:   {:04o}  (WARNING: readable by group/others; run `chmod 600`)",
                mode
            );
        } else {
            println!("  perms:   {:04o}", mode);
        }
    }
}

#[cfg(not(unix))]
fn print_permission_line(_path: &Path) {}

/// ACTIVE CREDENTIALS ブロック。
///
/// jamf-cli の "ACTIVE PROFILE" に相当する。splunk-cloud-cli には profile 概念が
/// 無いため、解決済みの接続先・認証方式・各秘密の出所を示す。秘密値は出さない。
///
/// 戻り値は「致命的な構成不備が無いか」。base_url 欠如や認証情報ゼロは false。
fn print_credentials_block(settings: &Settings, store: Option<&dyn CredentialStore>) -> bool {
    println!("ACTIVE CREDENTIALS");
    let mut healthy = true;

    // base_url（秘密ではない）。env → config の順で解決し、出所も示す。
    match resolve_base_url(settings) {
        Ok(url) => {
            let src = if env_set("SPLUNK_BASE_URL") {
                "env SPLUNK_BASE_URL"
            } else {
                "config base_url"
            };
            println!("  base-url:      {}  ({})", url, src);
        }
        Err(_) => {
            println!("  base-url:      (UNRESOLVABLE: set SPLUNK_BASE_URL or config `base_url`)");
            healthy = false;
        }
    }

    // 認証方式の判定。resolve_credentials と同じ優先順位を踏襲する:
    //   env SPLUNK_TOKEN → OAuth session → token(store/toml) → session_key → Basic。
    let token_src = secret_source("SPLUNK_TOKEN", store, KEY_TOKEN, settings.token.is_some());
    let oauth_present = oauth_session_present(store);
    let session_key_src = secret_source(
        "SPLUNK_SESSION_KEY",
        store,
        KEY_SESSION_KEY,
        settings.session_key.is_some(),
    );
    let password_src = secret_source(
        "SPLUNK_PASSWORD",
        store,
        KEY_PASSWORD,
        settings.password.is_some(),
    );
    let username = std::env::var("SPLUNK_USERNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| settings.username.clone());

    // store backend 障害があれば先に警告する。resolve_credentials は障害時に
    // toml フォールバックを拒否して認証情報を解決しない。auth-method 判定では
    // StoreUnreachable を「出所なし」として扱い（resolved_label が None）、
    // 偽の「認証できる」表示を避ける。ここで障害そのものを 1 行で告知する。
    for s in [&token_src, &session_key_src, &password_src] {
        if let SecretSource::StoreUnreachable(msg) = s {
            println!("  credential-store: UNREACHABLE ({})", msg);
            println!("                    Stored secrets cannot be read; config.toml is NOT");
            println!("                    used as a fallback. Fix store access and retry.");
            healthy = false;
            break;
        }
    }

    let env_token_set = env_set("SPLUNK_TOKEN");
    if let Some(src) = token_src.resolved_label() {
        // env SPLUNK_TOKEN は OAuth より優先される。
        if env_token_set {
            println!("  auth-method:   bearer-token  (from {})", src);
        } else if oauth_present {
            // token(store/toml) と OAuth session が両立する場合、resolve_credentials は
            // token を先に採用する。
            println!("  auth-method:   bearer-token  (from {})", src);
            println!("  oauth-session: stored  (not used; manual token takes precedence)");
        } else {
            println!("  auth-method:   bearer-token  (from {})", src);
        }
    } else if oauth_present {
        println!("  auth-method:   oauth2  (OAuth session in credential store)");
        print_oauth_config_line(settings);
    } else if let Some(src) = session_key_src.resolved_label() {
        println!("  auth-method:   session-key  (from {})", src);
    } else if let (Some(u), Some(src)) = (&username, password_src.resolved_label()) {
        println!(
            "  auth-method:   basic  (user={}, password from {})",
            u, src
        );
    } else {
        println!("  auth-method:   (NONE RESOLVABLE)");
        println!("                 Run `auth login`, or set SPLUNK_TOKEN /");
        println!("                 SPLUNK_SESSION_KEY / (SPLUNK_USERNAME + SPLUNK_PASSWORD),");
        println!("                 or store one via `credentials set`.");
        healthy = false;
    }

    // 既定 app / user（秘密ではない）。
    let app = first_non_empty(&[
        std::env::var("SPLUNK_APP").ok(),
        settings.default_app.clone(),
    ])
    .unwrap_or_else(|| "search".to_string());
    let user = first_non_empty(&[
        std::env::var("SPLUNK_USER").ok(),
        settings.default_user.clone(),
    ])
    .unwrap_or_else(|| "nobody".to_string());
    println!("  default-app:   {}", app);
    println!("  default-user:  {}", user);

    healthy
}

/// OAuth セッション利用時に tenant/client の設定状況を示す（秘密ではない）。
fn print_oauth_config_line(settings: &Settings) {
    let tenant = first_non_empty(&[
        std::env::var("SPLUNK_OAUTH_TENANT_ID").ok(),
        settings.oauth_tenant_id.clone(),
    ]);
    let client = first_non_empty(&[
        std::env::var("SPLUNK_OAUTH_CLIENT_ID").ok(),
        settings.oauth_client_id.clone(),
    ]);
    println!(
        "  oauth-tenant:  {}",
        tenant.as_deref().unwrap_or("(unset)")
    );
    println!(
        "  oauth-client:  {}",
        client.as_deref().unwrap_or("(unset)")
    );
}

/// ENVIRONMENT ブロック。SPLUNK_* 環境変数の set/unset を一覧する。
/// 秘密値の環境変数は値を出さず set/unset のみ示す。
fn print_environment_block() {
    println!("ENVIRONMENT");
    for key in NON_SECRET_ENV {
        match std::env::var(key) {
            Ok(v) if !v.is_empty() => println!("  {:30} {}", key, v),
            _ => println!("  {:30} (unset)", key),
        }
    }
    // SPLUNK_USERNAME は秘密ではないが、認証ペアの片割れなので非秘密側に並べる。
    match std::env::var("SPLUNK_USERNAME") {
        Ok(v) if !v.is_empty() => println!("  {:30} {}", "SPLUNK_USERNAME", v),
        _ => println!("  {:30} (unset)", "SPLUNK_USERNAME"),
    }
    for key in SECRET_ENV {
        if env_set(key) {
            println!("  {:30} (set)", key);
        } else {
            println!("  {:30} (unset)", key);
        }
    }
}

/// CONNECTIVITY ブロック。base_url へ HEAD して status と所要時間を出す。
/// 認証は付けない（到達性のみ確認）。401 は「到達はできている」と解釈する。
///
/// 戻り値は「接続が健全か」。接続不能（DNS/TLS/timeout）のときだけ false。
/// 401/403 は到達できているので true 扱い。
async fn print_connectivity_block(settings: &Settings) -> bool {
    println!("CONNECTIVITY");
    let base_url = match resolve_base_url(settings) {
        Ok(u) => u,
        Err(_) => {
            println!("  (skipped: base_url not set)");
            return false;
        }
    };

    let client = match reqwest::Client::builder()
        .user_agent(concat!("splunk-cloud-cli/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            println!("  HEAD {}  ->  client build failed: {}", base_url, e);
            return false;
        }
    };

    let started = Instant::now();
    let result = client.head(&base_url).send().await;
    let elapsed = started.elapsed().as_millis();

    match result {
        Ok(resp) => {
            let status = resp.status();
            println!("  HEAD {}  ->  {} ({}ms)", base_url, status, elapsed);
            // 到達はできている。401/403 は資格情報の問題で、接続性そのものは健全。
            true
        }
        Err(e) => {
            let reason = connect_error_reason(&e);
            println!("  HEAD {}  ->  {} ({}ms)", base_url, reason, elapsed);
            false
        }
    }
}

/// reqwest のエラーを人間向けの短い理由文に落とす。
fn connect_error_reason(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "timed out".to_string()
    } else if e.is_connect() {
        format!("connection failed: {}", e)
    } else {
        format!("request failed: {}", e)
    }
}

/// 環境変数が空でない値で設定されているか。
fn env_set(key: &str) -> bool {
    std::env::var(key).map(|v| !v.is_empty()).unwrap_or(false)
}

/// 秘密フィールドの解決結果。`resolve_secret` の挙動と 1:1 で対応させる。
///
/// 重要なのは `StoreUnreachable` を「採用可能な出所」と混同しないこと。
/// `resolve_secret` は store backend エラー時に `None`（= 解決不能）を返し、
/// toml フォールバックも拒否する。doctor もこれに合わせ、`StoreUnreachable` は
/// auth-method を構成しない（実コマンドが `no credential set` で失敗する状態を
/// 「認証できる」と偽らないため）。
enum SecretSource {
    /// 採用可能な出所が見つかった（env / credential store / config.toml）。
    Resolved(String),
    /// store backend 障害で解決不能。toml に書いてあっても採用されない。
    StoreUnreachable(String),
    /// どこにも無い。
    Absent,
}

impl SecretSource {
    /// 採用可能な出所の表示文字列。auth-method を構成できる場合のみ `Some`。
    fn resolved_label(&self) -> Option<&str> {
        match self {
            SecretSource::Resolved(s) => Some(s),
            SecretSource::StoreUnreachable(_) | SecretSource::Absent => None,
        }
    }
}

/// 秘密フィールドの出所を、resolve_secret と同じ優先順位（env → store → toml）で
/// 判定する。秘密値そのものは読まない／返さない。
///
/// env で上書きされていれば store/toml は見ない（resolve_secret の挙動に合わせる）。
/// store backend エラーは `StoreUnreachable` として返し、resolve_secret が
/// toml フォールバックを拒否する挙動と一致させる。
fn secret_source(
    env_key: &str,
    store: Option<&dyn CredentialStore>,
    store_key: &str,
    in_toml: bool,
) -> SecretSource {
    if env_set(env_key) {
        return SecretSource::Resolved(format!("env {}", env_key));
    }
    match store_has(store, store_key) {
        StorePresence::Found => SecretSource::Resolved("credential store".to_string()),
        StorePresence::BackendError(msg) => SecretSource::StoreUnreachable(msg),
        StorePresence::NotFound => {
            if in_toml {
                SecretSource::Resolved("config.toml".to_string())
            } else {
                SecretSource::Absent
            }
        }
    }
}

/// store に OAuth セッションが保存されているか（値は読まない）。
fn oauth_session_present(store: Option<&dyn CredentialStore>) -> bool {
    matches!(store_has(store, KEY_OAUTH_SESSION), StorePresence::Found)
}

enum StorePresence {
    Found,
    NotFound,
    BackendError(String),
}

/// store にキーが存在するかだけを確認する。値そのものは取り出すが返さない。
fn store_has(store: Option<&dyn CredentialStore>, key: &str) -> StorePresence {
    let Some(store) = store else {
        return StorePresence::NotFound;
    };
    match store.get(key) {
        Ok(Some(v)) if !v.is_empty() => StorePresence::Found,
        Ok(_) => StorePresence::NotFound,
        Err(StoreError::Unavailable(_)) => StorePresence::NotFound,
        Err(StoreError::Backend(msg)) => StorePresence::BackendError(msg),
    }
}

/// 候補のうち空でない最初の値を返す。config/mod.rs の同名ヘルパと同じ意図。
fn first_non_empty(candidates: &[Option<String>]) -> Option<String> {
    candidates.iter().flatten().find(|s| !s.is_empty()).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::credential_store::test_support::{
        FailingStore, MemoryStore, UnavailableStore,
    };
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn clear_env() {
        for k in [
            "SPLUNK_TOKEN",
            "SPLUNK_SESSION_KEY",
            "SPLUNK_PASSWORD",
            "SPLUNK_BASE_URL",
        ] {
            unsafe {
                std::env::remove_var(k);
            }
        }
    }

    #[test]
    fn secret_source_prefers_env() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        unsafe {
            std::env::set_var("SPLUNK_TOKEN", "x");
        }
        let store = MemoryStore::new();
        store.set(KEY_TOKEN, "from-store").unwrap();
        let src = secret_source("SPLUNK_TOKEN", Some(&store), KEY_TOKEN, true);
        assert_eq!(src.resolved_label(), Some("env SPLUNK_TOKEN"));
        unsafe {
            std::env::remove_var("SPLUNK_TOKEN");
        }
    }

    #[test]
    fn secret_source_reports_store() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        let store = MemoryStore::new();
        store.set(KEY_TOKEN, "from-store").unwrap();
        let src = secret_source("SPLUNK_TOKEN", Some(&store), KEY_TOKEN, true);
        assert_eq!(src.resolved_label(), Some("credential store"));
    }

    #[test]
    fn secret_source_falls_back_to_toml() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        let store = MemoryStore::new();
        let src = secret_source("SPLUNK_TOKEN", Some(&store), KEY_TOKEN, true);
        assert_eq!(src.resolved_label(), Some("config.toml"));
    }

    #[test]
    fn secret_source_none_when_nowhere() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        let store = MemoryStore::new();
        let src = secret_source("SPLUNK_TOKEN", Some(&store), KEY_TOKEN, false);
        assert!(matches!(src, SecretSource::Absent));
        assert!(src.resolved_label().is_none());
    }

    #[test]
    fn secret_source_backend_error_is_unreachable_and_not_resolvable() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        let store = FailingStore;
        // store backend エラー時は StoreUnreachable を返す。toml に書いてあっても
        // 採用しない（resolved_label が None）。これが resolve_secret の
        // BackendError → None と一致する核心。auth-method を偽って構成しない。
        let src = secret_source("SPLUNK_TOKEN", Some(&store), KEY_TOKEN, true);
        assert!(
            matches!(src, SecretSource::StoreUnreachable(_)),
            "expected StoreUnreachable"
        );
        assert!(
            src.resolved_label().is_none(),
            "store-unreachable must not be a usable source"
        );
    }

    #[test]
    fn secret_source_unavailable_store_falls_back_to_toml() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        let store = UnavailableStore;
        // Unavailable（非 macOS / default keychain 無し）は store 非搭載扱い。
        // toml フォールバックを許す（resolve_secret と一致）。
        let src = secret_source("SPLUNK_TOKEN", Some(&store), KEY_TOKEN, true);
        assert_eq!(src.resolved_label(), Some("config.toml"));
    }

    #[test]
    fn never_returns_secret_value() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        unsafe {
            std::env::set_var("SPLUNK_TOKEN", "SUPER_SECRET_VALUE");
        }
        let store = MemoryStore::new();
        store.set(KEY_TOKEN, "STORE_SECRET").unwrap();
        let src = secret_source("SPLUNK_TOKEN", Some(&store), KEY_TOKEN, true);
        let label = src.resolved_label().unwrap();
        assert!(!label.contains("SUPER_SECRET_VALUE"));
        assert!(!label.contains("STORE_SECRET"));
        unsafe {
            std::env::remove_var("SPLUNK_TOKEN");
        }
    }

    #[test]
    fn oauth_session_present_detects_entry() {
        let store = MemoryStore::new();
        assert!(!oauth_session_present(Some(&store)));
        store.set(KEY_OAUTH_SESSION, "{\"x\":1}").unwrap();
        assert!(oauth_session_present(Some(&store)));
    }

    #[test]
    fn first_non_empty_skips_empty() {
        assert_eq!(
            first_non_empty(&[Some("".into()), Some("y".into())]).as_deref(),
            Some("y")
        );
        assert!(first_non_empty(&[None, Some("".into())]).is_none());
    }
}

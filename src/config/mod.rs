use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::cli::OutputFormat;
use crate::error::{Result, SplunkError};

pub mod credential_store;

use credential_store::{
    default_store, CredentialStore, StoreError, KEY_PASSWORD, KEY_SESSION_KEY, KEY_TOKEN,
};

/// Splunk Cloud への接続に必要な資格情報一式。
#[derive(Debug, Clone)]
pub struct Credentials {
    pub base_url: String,
    pub auth: AuthMethod,
    pub default_app: String,
    pub default_user: String,
}

/// 認証方式。計画書の 3 系統に対応する。
#[derive(Clone)]
pub enum AuthMethod {
    /// `Authorization: Bearer <token>` を送る Splunk 認証トークン。推奨。
    BearerToken(String),
    /// `Authorization: Splunk <session_key>` を送るセッションキー。
    SessionKey(String),
    /// `/services/auth/login` に username/password を送ってセッションキーを得る。
    Basic { username: String, password: String },
}

/// `AuthMethod` は機密値を保持する。`{:?}` 経由でログやエラー文字列に混入しないよう、
/// 値そのものは常に `***` に置き換え、バリアントの種類だけを出す。
impl std::fmt::Debug for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthMethod::BearerToken(_) => f.debug_tuple("BearerToken").field(&"***").finish(),
            AuthMethod::SessionKey(_) => f.debug_tuple("SessionKey").field(&"***").finish(),
            AuthMethod::Basic { username, .. } => f
                .debug_struct("Basic")
                .field("username", username)
                .field("password", &"***")
                .finish(),
        }
    }
}

/// 設定ファイル（TOML）の表現。
///
/// 挙動の既定値に加えて、接続先・認証情報も保持できる。
/// 環境変数が設定されていればそちらを優先する。
/// CLI フラグで受け取る口は存在しない（`ps` / shell 履歴漏洩対策）。
///
/// **平文で秘密情報が載るので `chmod 600` を推奨する。** さらに推奨するのは、
/// macOS Keychain に token / session_key / password を退避して TOML から
/// 該当行を消してしまう方針（`splunk-cloud-cli credentials migrate`）。
#[derive(Clone, Default, Deserialize, Serialize)]
pub struct Settings {
    // --- 接続先 ---
    /// 例: `https://<stack>.splunkcloud.com:8089`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,

    // --- 認証（いずれか一つ） ---
    /// Bearer token。`Authorization: Bearer <token>` として送る。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Session key。`Authorization: Splunk <key>` として送る。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_key: Option<String>,
    /// Basic 認証ユーザー名。`/services/auth/login` で session key を取得する。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Basic 認証パスワード。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    // --- 挙動 ---
    /// servicesNS 用の既定 app。未指定時は "search"。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_app: Option<String>,
    /// servicesNS 用の既定 user。未指定時は "nobody"。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_user: Option<String>,
    /// 既定の出力フォーマット。未指定時は `pretty`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<OutputFormat>,
}

/// `Settings` は機密値（token / session_key / password）を含む可能性があるため、
/// `{:?}` で値が流出しないよう手書きの `Debug` でマスクする。
impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings")
            .field("base_url", &self.base_url)
            .field("token", &mask(&self.token))
            .field("session_key", &mask(&self.session_key))
            .field("username", &self.username)
            .field("password", &mask(&self.password))
            .field("default_app", &self.default_app)
            .field("default_user", &self.default_user)
            .field("format", &self.format)
            .finish()
    }
}

fn mask(v: &Option<String>) -> &'static str {
    match v {
        Some(_) => "***",
        None => "None",
    }
}

/// 設定ファイルの探索パス（優先度順）。
///
/// 1. カレントディレクトリの `.splunk-cloud-cli.toml`
/// 2. `$XDG_CONFIG_HOME/splunk-cloud-cli/config.toml`
/// 3. `~/.config/splunk-cloud-cli/config.toml`
pub fn config_search_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from(".splunk-cloud-cli.toml")];
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        paths.push(
            PathBuf::from(xdg)
                .join("splunk-cloud-cli")
                .join("config.toml"),
        );
    } else if let Some(home) = dirs::home_dir() {
        paths.push(
            home.join(".config")
                .join("splunk-cloud-cli")
                .join("config.toml"),
        );
    }
    paths
}

/// 設定ファイルを探して最初に見つかったものを読み込む。
///
/// 存在しない場合は `Settings::default()` を返す（エラーにしない）。
/// TOML パースエラーは明示的に伝播させる。
///
/// ファイル権限が他ユーザーから読める状態だと秘密情報が漏れるため、
/// 秘密情報を含むファイルがワールドリーダブルなら `stderr` に警告を出す。
pub fn load_settings() -> Result<Settings> {
    for path in config_search_paths() {
        if !path.exists() {
            continue;
        }
        let content = std::fs::read_to_string(&path)?;
        let settings: Settings = toml::from_str(&content).map_err(|e| {
            SplunkError::Config(format!("failed to parse {}: {}", path.display(), e))
        })?;
        if settings.has_secret() {
            warn_if_world_readable(&path);
        }
        return Ok(settings);
    }
    Ok(Settings::default())
}

impl Settings {
    /// いずれかの秘密情報フィールドが埋まっているか。
    fn has_secret(&self) -> bool {
        self.token.is_some() || self.session_key.is_some() || self.password.is_some()
    }
}

#[cfg(unix)]
fn warn_if_world_readable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode() & 0o777;
        // 他ユーザー or グループが読める場合は警告。
        if mode & 0o077 != 0 {
            eprintln!(
                "warning: {} is readable by group/others (mode={:04o}). \
Run `chmod 600 {}` to protect secrets.",
                path.display(),
                mode,
                path.display()
            );
        }
    }
}

#[cfg(not(unix))]
fn warn_if_world_readable(_path: &std::path::Path) {}

/// 機密情報ストア参照の結果を優先順位に載せるために使う内部型。
enum StoreLookup {
    /// ストア未搭載（非 macOS ビルド等）。次のソースへフォールスルーしてよい。
    SkipFallthrough,
    /// ストアは到達可能だがエントリが無い。次のソースへフォールスルー。
    NotStored,
    /// ストアから値を取得できた。
    Found(String),
    /// バックエンド障害（Keychain アクセス拒否など）。
    /// ここで TOML にフォールスルーしてしまうと「移行したつもりの古い平文」を
    /// 黙って拾ってしまうので、呼び出し側には `None` を返して
    /// 「資格情報が設定されていない」ことを明示する。
    BackendError,
}

fn read_secret_from_store(store: Option<&dyn CredentialStore>, key: &str) -> StoreLookup {
    let Some(store) = store else {
        return StoreLookup::SkipFallthrough;
    };
    match store.get(key) {
        Ok(Some(v)) => StoreLookup::Found(v),
        Ok(None) => StoreLookup::NotStored,
        Err(StoreError::Unavailable(msg)) => {
            // `key` は静的識別子（"token" など）で機密値ではない。
            eprintln!("warning: credential store unavailable for {}: {}", key, msg);
            StoreLookup::SkipFallthrough
        }
        Err(StoreError::Backend(msg)) => {
            eprintln!(
                "error: credential store backend failure for {}: {}. \
                 Refusing to fall back to config.toml — fix the store \
                 access or unset the entry to make the toml fallback explicit.",
                key, msg
            );
            StoreLookup::BackendError
        }
    }
}

/// 「env → Keychain → TOML」の優先順でフィールドを解決する。
/// Backend エラーの場合のみ TOML へのフォールバックを拒否する。
fn resolve_secret(
    env_value: Option<String>,
    store: Option<&dyn CredentialStore>,
    key: &str,
    toml_value: Option<String>,
) -> Option<String> {
    if env_value.is_some() {
        return env_value;
    }
    match read_secret_from_store(store, key) {
        StoreLookup::Found(v) => Some(v),
        StoreLookup::BackendError => None,
        StoreLookup::SkipFallthrough | StoreLookup::NotStored => toml_value,
    }
}

/// 環境変数・Keychain・設定ファイルから資格情報を解決する。
///
/// 認証情報は CLI フラグでは受け取らない（`ps` / shell 履歴漏洩対策）。
///
/// `token` / `session_key` / `password` の優先度:
///   env var > OS credential store > config.toml > None
/// `base_url` / `username` / `default_app` / `default_user` の優先度:
///   CLI（対象のみ） > env var > config.toml > 既定値
///
/// 必須:
///   - `SPLUNK_BASE_URL` または TOML の `base_url`
///   - 以下のいずれか:
///     - `SPLUNK_TOKEN` / TOML `token` / Keychain `token`
///     - `SPLUNK_SESSION_KEY` / TOML `session_key` / Keychain `session_key`
///     - `SPLUNK_USERNAME` + (`SPLUNK_PASSWORD` / TOML `password` / Keychain `password`)
///
/// 任意:
///   - `default_app` / `SPLUNK_APP`（既定 "search"）
///   - `default_user` / `SPLUNK_USER`（既定 "nobody"）
pub fn resolve_credentials(
    cli_default_app: Option<&str>,
    cli_default_user: Option<&str>,
    settings: &Settings,
) -> Result<Credentials> {
    resolve_credentials_with_store(
        cli_default_app,
        cli_default_user,
        settings,
        default_store().as_deref(),
    )
}

/// ストアを注入できる版の `resolve_credentials`。テストから使う。
pub fn resolve_credentials_with_store(
    cli_default_app: Option<&str>,
    cli_default_user: Option<&str>,
    settings: &Settings,
    store: Option<&dyn CredentialStore>,
) -> Result<Credentials> {
    let base_url = std::env::var("SPLUNK_BASE_URL")
        .ok()
        .or_else(|| settings.base_url.clone())
        .ok_or_else(|| {
            SplunkError::Config(
                "base_url not set. Set SPLUNK_BASE_URL or `base_url` in the config file. \
Example: export SPLUNK_BASE_URL=https://<stack>.splunkcloud.com:8089"
                    .to_string(),
            )
        })?;

    let token = resolve_secret(
        std::env::var("SPLUNK_TOKEN").ok(),
        store,
        KEY_TOKEN,
        settings.token.clone(),
    );
    let session_key = resolve_secret(
        std::env::var("SPLUNK_SESSION_KEY").ok(),
        store,
        KEY_SESSION_KEY,
        settings.session_key.clone(),
    );
    let username = std::env::var("SPLUNK_USERNAME")
        .ok()
        .or_else(|| settings.username.clone());
    let password = resolve_secret(
        std::env::var("SPLUNK_PASSWORD").ok(),
        store,
        KEY_PASSWORD,
        settings.password.clone(),
    );

    let auth = if let Some(t) = token {
        AuthMethod::BearerToken(t)
    } else if let Some(sk) = session_key {
        AuthMethod::SessionKey(sk)
    } else if let (Some(u), Some(p)) = (username, password) {
        AuthMethod::Basic {
            username: u,
            password: p,
        }
    } else {
        return Err(SplunkError::Config(
            "no credential set. Set one of SPLUNK_TOKEN / SPLUNK_SESSION_KEY / \
(SPLUNK_USERNAME + SPLUNK_PASSWORD), or `token` / `session_key` / (`username` + `password`) \
in the config file, or store one via `splunk-cloud-cli credentials set`."
                .to_string(),
        ));
    };

    let default_app = first_non_empty(&[
        cli_default_app.map(String::from),
        std::env::var("SPLUNK_APP").ok(),
        settings.default_app.clone(),
    ])
    .unwrap_or_else(|| "search".to_string());
    let default_user = first_non_empty(&[
        cli_default_user.map(String::from),
        std::env::var("SPLUNK_USER").ok(),
        settings.default_user.clone(),
    ])
    .unwrap_or_else(|| "nobody".to_string());

    Ok(Credentials {
        base_url,
        auth,
        default_app,
        default_user,
    })
}

/// 候補のうち空文字でない最初の値を返す。空文字を「未設定」として扱うことで、
/// 設定ファイルに `default_user = ""` のような空値があっても既定値へフォールバックする。
fn first_non_empty(candidates: &[Option<String>]) -> Option<String> {
    candidates.iter().flatten().find(|s| !s.is_empty()).cloned()
}

#[cfg(test)]
mod tests {
    use super::credential_store::test_support::MemoryStore;
    use super::*;
    use std::sync::Mutex;

    /// resolve 系テストは HOME / XDG_CONFIG_HOME / SPLUNK_* を触るため、
    /// cargo test のデフォルトスレッドプールで並列実行すると順序依存になる。
    /// 直列化のため共有 Mutex を用意する。
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn clear_splunk_env() {
        for k in [
            "SPLUNK_BASE_URL",
            "SPLUNK_TOKEN",
            "SPLUNK_SESSION_KEY",
            "SPLUNK_USERNAME",
            "SPLUNK_PASSWORD",
            "SPLUNK_APP",
            "SPLUNK_USER",
        ] {
            // Safety: テスト内でのみ使う。
            unsafe {
                std::env::remove_var(k);
            }
        }
    }

    #[test]
    fn parse_settings_full() {
        let toml = r#"
base_url = "https://test.splunkcloud.com:8089"
token = "t"
default_app = "my_app"
default_user = "admin"
format = "json"
"#;
        let settings: Settings = toml::from_str(toml).unwrap();
        assert_eq!(
            settings.base_url.as_deref(),
            Some("https://test.splunkcloud.com:8089")
        );
        assert_eq!(settings.token.as_deref(), Some("t"));
        assert_eq!(settings.default_app.as_deref(), Some("my_app"));
        assert_eq!(settings.default_user.as_deref(), Some("admin"));
        assert!(matches!(settings.format, Some(OutputFormat::Json)));
    }

    #[test]
    fn parse_settings_empty() {
        let settings: Settings = toml::from_str("").unwrap();
        assert!(settings.base_url.is_none());
        assert!(settings.token.is_none());
        assert!(settings.default_app.is_none());
        assert!(settings.format.is_none());
    }

    #[test]
    fn has_secret_detects_token() {
        let mut s = Settings::default();
        assert!(!s.has_secret());
        s.token = Some("x".into());
        assert!(s.has_secret());
    }

    #[test]
    fn first_non_empty_skips_empty_strings() {
        assert_eq!(
            first_non_empty(&[Some("".into()), Some("x".into())]),
            Some("x".to_string())
        );
        assert_eq!(
            first_non_empty(&[None, Some("".into()), Some("y".into())]),
            Some("y".to_string())
        );
        assert_eq!(first_non_empty(&[None, Some("".into())]), None);
    }

    #[test]
    fn has_secret_ignores_non_secret_fields() {
        let s = Settings {
            base_url: Some("u".into()),
            default_app: Some("a".into()),
            ..Settings::default()
        };
        assert!(!s.has_secret());
    }

    #[test]
    fn debug_masks_secrets() {
        let s = Settings {
            base_url: Some("https://x".into()),
            token: Some("SUPER_SECRET".into()),
            session_key: Some("SK".into()),
            password: Some("PW".into()),
            username: Some("alice".into()),
            ..Settings::default()
        };
        let rendered = format!("{:?}", s);
        assert!(!rendered.contains("SUPER_SECRET"));
        assert!(!rendered.contains("SK"));
        assert!(!rendered.contains("PW"));
        assert!(rendered.contains("alice"));
    }

    #[test]
    fn auth_method_debug_does_not_leak_value() {
        let m = AuthMethod::BearerToken("TOKEN_VALUE".into());
        let rendered = format!("{:?}", m);
        assert!(!rendered.contains("TOKEN_VALUE"));
        assert!(rendered.contains("BearerToken"));
    }

    #[test]
    fn resolve_prefers_store_over_toml() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_splunk_env();
        let store = MemoryStore::new();
        store.set(KEY_TOKEN, "from-store").unwrap();

        let settings = Settings {
            base_url: Some("https://x.splunkcloud.com:8089".into()),
            token: Some("from-toml".into()),
            ..Settings::default()
        };
        let creds = resolve_credentials_with_store(
            None,
            None,
            &settings,
            Some(&store as &dyn CredentialStore),
        )
        .unwrap();
        match creds.auth {
            AuthMethod::BearerToken(t) => assert_eq!(t, "from-store"),
            _ => panic!("expected BearerToken"),
        }
    }

    #[test]
    fn resolve_env_overrides_store() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_splunk_env();
        // Safety: テスト内でのみ使う。
        unsafe {
            std::env::set_var("SPLUNK_TOKEN", "from-env");
        }
        let store = MemoryStore::new();
        store.set(KEY_TOKEN, "from-store").unwrap();

        let settings = Settings {
            base_url: Some("https://x.splunkcloud.com:8089".into()),
            ..Settings::default()
        };
        let creds = resolve_credentials_with_store(
            None,
            None,
            &settings,
            Some(&store as &dyn CredentialStore),
        )
        .unwrap();
        match creds.auth {
            AuthMethod::BearerToken(t) => assert_eq!(t, "from-env"),
            _ => panic!("expected BearerToken"),
        }
        // Safety: テスト内でのみ使う。
        unsafe {
            std::env::remove_var("SPLUNK_TOKEN");
        }
    }

    #[test]
    fn resolve_falls_back_to_toml_when_store_empty() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_splunk_env();
        let store = MemoryStore::new();
        let settings = Settings {
            base_url: Some("https://x.splunkcloud.com:8089".into()),
            token: Some("from-toml".into()),
            ..Settings::default()
        };
        let creds = resolve_credentials_with_store(
            None,
            None,
            &settings,
            Some(&store as &dyn CredentialStore),
        )
        .unwrap();
        match creds.auth {
            AuthMethod::BearerToken(t) => assert_eq!(t, "from-toml"),
            _ => panic!("expected BearerToken"),
        }
    }

    #[test]
    fn resolve_session_key_via_store() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_splunk_env();
        let store = MemoryStore::new();
        store.set(KEY_SESSION_KEY, "sk-from-store").unwrap();
        let settings = Settings {
            base_url: Some("https://x.splunkcloud.com:8089".into()),
            ..Settings::default()
        };
        let creds = resolve_credentials_with_store(
            None,
            None,
            &settings,
            Some(&store as &dyn CredentialStore),
        )
        .unwrap();
        match creds.auth {
            AuthMethod::SessionKey(sk) => assert_eq!(sk, "sk-from-store"),
            _ => panic!("expected SessionKey"),
        }
    }

    #[test]
    fn resolve_basic_password_via_store() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_splunk_env();
        let store = MemoryStore::new();
        store.set(KEY_PASSWORD, "pw-from-store").unwrap();
        let settings = Settings {
            base_url: Some("https://x.splunkcloud.com:8089".into()),
            username: Some("alice".into()),
            ..Settings::default()
        };
        let creds = resolve_credentials_with_store(
            None,
            None,
            &settings,
            Some(&store as &dyn CredentialStore),
        )
        .unwrap();
        match creds.auth {
            AuthMethod::Basic { username, password } => {
                assert_eq!(username, "alice");
                assert_eq!(password, "pw-from-store");
            }
            _ => panic!("expected Basic"),
        }
    }
}

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::cli::OutputFormat;
use crate::error::{Result, SplunkError};

/// Splunk Cloud への接続に必要な資格情報一式。
#[derive(Debug, Clone)]
pub struct Credentials {
    pub base_url: String,
    pub auth: AuthMethod,
    pub default_app: String,
    pub default_user: String,
}

/// 認証方式。計画書の 3 系統に対応する。
#[derive(Debug, Clone)]
pub enum AuthMethod {
    /// `Authorization: Bearer <token>` を送る Splunk 認証トークン。推奨。
    BearerToken(String),
    /// `Authorization: Splunk <session_key>` を送るセッションキー。
    SessionKey(String),
    /// `/services/auth/login` に username/password を送ってセッションキーを得る。
    Basic { username: String, password: String },
}

/// 設定ファイル（TOML）の表現。
///
/// 挙動の既定値に加えて、接続先・認証情報も保持できる。
/// 環境変数が設定されていればそちらを優先する。
/// CLI フラグで受け取る口は存在しない（`ps` / shell 履歴漏洩対策）。
///
/// **平文で秘密情報が載るので `chmod 600` を推奨する。**
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
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

/// 環境変数と設定ファイルから資格情報を解決する。
///
/// 認証情報は CLI フラグでは受け取らない（`ps` / shell 履歴漏洩対策）。
///
/// 優先度: 環境変数 → 設定ファイル → 既定値（ただし必須項目は既定値なし）。
///
/// 必須:
///   - `SPLUNK_BASE_URL` または TOML の `base_url`
///   - `SPLUNK_TOKEN` / `SPLUNK_SESSION_KEY` / (`SPLUNK_USERNAME` + `SPLUNK_PASSWORD`)
///     または TOML の `token` / `session_key` / (`username` + `password`) のいずれか
///
/// 任意:
///   - `default_app` / `SPLUNK_APP`（既定 "search"）
///   - `default_user` / `SPLUNK_USER`（既定 "nobody"）
pub fn resolve_credentials(
    cli_default_app: Option<&str>,
    cli_default_user: Option<&str>,
    settings: &Settings,
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

    let token = std::env::var("SPLUNK_TOKEN")
        .ok()
        .or_else(|| settings.token.clone());
    let session_key = std::env::var("SPLUNK_SESSION_KEY")
        .ok()
        .or_else(|| settings.session_key.clone());
    let username = std::env::var("SPLUNK_USERNAME")
        .ok()
        .or_else(|| settings.username.clone());
    let password = std::env::var("SPLUNK_PASSWORD")
        .ok()
        .or_else(|| settings.password.clone());

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
in the config file."
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
    use super::*;

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
}

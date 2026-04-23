//! `splunk-cloud-cli credentials` サブコマンドのハンドラ。
//!
//! - `set`: Keychain へ値を書く（対話 / stdin）。
//! - `delete`: Keychain から値を消す。
//! - `status`: 各フィールドが保存されているかを印字する（値は決して出さない）。
//! - `migrate`: config.toml 上の機密行を Keychain に移し、Keychain 書込成功後のみ
//!   原本を atomic に書き換える。途中で失敗した場合は Keychain 側をロールバックし、
//!   原本は無傷のまま残す。

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cli::{CredentialField, CredentialsCmd};
use crate::config::config_search_paths;
use crate::config::credential_store::{
    default_store, CredentialStore, KEY_PASSWORD, KEY_SESSION_KEY, KEY_TOKEN,
};
use crate::error::{Result, SplunkError};

/// 平文機密を含みうるファイルの permission。
const SECRET_FILE_MODE: u32 = 0o600;

/// `credentials` サブコマンドのエントリポイント。
pub fn run(cmd: &CredentialsCmd) -> Result<()> {
    let store = default_store().ok_or_else(|| {
        SplunkError::Config(
            "no credential store backend available on this platform (macOS Keychain required)"
                .to_string(),
        )
    })?;

    match cmd {
        CredentialsCmd::Set { field, stdin } => set_value(store.as_ref(), *field, *stdin),
        CredentialsCmd::Delete { field } => delete_value(store.as_ref(), *field),
        CredentialsCmd::Status => print_status(store.as_ref()),
        CredentialsCmd::Migrate { dry_run } => migrate(store.as_ref(), *dry_run),
    }
}

fn set_value(store: &dyn CredentialStore, field: CredentialField, from_stdin: bool) -> Result<()> {
    let value = if from_stdin {
        let mut buf = String::new();
        io::stdin().read_line(&mut buf)?;
        // 行末の `\n` / `\r\n` だけを落とす。`trim()` で先頭/末尾の空白を
        // 丸ごと削ると、前後スペースを含む正規の秘密値（稀だが）を静かに
        // 破壊する。意図的な空白はユーザーの値として尊重する。
        let stripped = buf.trim_end_matches(['\r', '\n']).to_string();
        if stripped.is_empty() {
            return Err(SplunkError::Config("empty value from stdin".to_string()));
        }
        stripped
    } else {
        let prompt = format!("Enter {} (input hidden): ", field.key());
        rpassword::prompt_password(prompt)
            .map_err(|e| SplunkError::Config(format!("failed to read password: {}", e)))?
    };

    if value.is_empty() {
        return Err(SplunkError::Config("empty value".to_string()));
    }

    store
        .set(field.key(), &value)
        .map_err(|e| SplunkError::Config(e.to_string()))?;
    println!("Stored {} in credential store", field.key());
    Ok(())
}

fn delete_value(store: &dyn CredentialStore, field: CredentialField) -> Result<()> {
    store
        .delete(field.key())
        .map_err(|e| SplunkError::Config(e.to_string()))?;
    println!("Deleted {} from credential store", field.key());
    Ok(())
}

fn print_status(store: &dyn CredentialStore) -> Result<()> {
    // 値そのものは一切出さず、静的キー名と存在フラグだけを示す。
    let keys = [KEY_TOKEN, KEY_SESSION_KEY, KEY_PASSWORD];
    println!("Credential store: macOS Keychain (service=dev.splunk-cloud-cli)");
    for key in keys {
        match store.get(key) {
            Ok(Some(_)) => println!("  {} : stored", key),
            Ok(None) => println!("  {} : not stored", key),
            Err(e) => println!("  {} : error ({})", key, e),
        }
    }
    Ok(())
}

/// config.toml から機密フィールドを Keychain に退避して、原本の該当行を消す。
///
/// 方針:
/// 1. 先に Keychain へ書く（toml は未変更なので失敗しても無傷）。
/// 2. ユーザーに「原本の扱い（削除 or バックアップ残し）」を聞く。
/// 3. rewrite 失敗時は Keychain の該当エントリをロールバックする。
fn migrate(store: &dyn CredentialStore, dry_run: bool) -> Result<()> {
    let path = find_config_toml().ok_or_else(|| {
        SplunkError::Config(
            "no config.toml found to migrate from. \
             To store a secret directly in the Keychain, run: \
             splunk-cloud-cli credentials set <field>"
                .to_string(),
        )
    })?;
    let canonical = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
    println!("Found config.toml: {}", canonical.display());

    let original = fs::read_to_string(&path).map_err(|e| {
        SplunkError::Config(format!("failed to read {}: {}", canonical.display(), e))
    })?;

    // 3 フィールドを一括で走査する。`Unsupported` はフィールドごとに即座にエラーにして、
    // 「片方だけ成功して片方は壊れた toml を残す」ような中途半端を避ける。
    let targets = [
        (KEY_TOKEN, "token"),
        (KEY_SESSION_KEY, "session_key"),
        (KEY_PASSWORD, "password"),
    ];
    let mut present: Vec<(&'static str, String)> = Vec::new();
    for (store_key, toml_key) in targets {
        match extract_field(&original, toml_key) {
            FieldScan::Present(v) => {
                println!("  {}: present (will move to credential store)", toml_key);
                present.push((store_key, v));
            }
            FieldScan::Absent => {
                println!("  {}: not present (skip)", toml_key);
            }
            FieldScan::Unsupported(form) => {
                return Err(SplunkError::Config(format!(
                    "{} uses an unsupported quoting form ({}); refusing to rewrite. \
                     Convert it to `{} = \"...\"` form and retry.",
                    toml_key, form, toml_key
                )));
            }
        }
    }

    if present.is_empty() {
        println!();
        println!(
            "No secrets to migrate. If you want to store a secret in the Keychain anyway, run: \
             splunk-cloud-cli credentials set <field>"
        );
        return Ok(());
    }

    if dry_run {
        println!("(dry-run) no changes made");
        return Ok(());
    }

    if !prompt_yes_no(
        &format!(
            "Migrate {} secret(s) from {} to the credential store?",
            present.len(),
            canonical.display()
        ),
        false,
    )? {
        println!("Aborted.");
        return Ok(());
    }

    // Step 1: 先に Keychain へ書く。この時点で失敗したらロールバックして終了。
    let mut written: Vec<&'static str> = Vec::new();
    for (store_key, value) in &present {
        if let Err(e) = store.set(store_key, value) {
            rollback_store(store, &written);
            return Err(SplunkError::Config(format!(
                "credential store: failed to write {}: {}. \
                 Rolled back any partially-written entries.",
                store_key, e
            )));
        }
        written.push(*store_key);
        println!("Stored {} in credential store", store_key);
    }

    // Step 2: 原本の処分方法を確認。既定は安全側（削除）。
    // 3 つの秘密キーは値の有無を問わず一律で原本から消す。`token = ""` のような
    // 空文字宣言行を残すと「秘密情報はどこにも書いてないはずなのに宣言だけ残る」
    // という誤解を招き、`credentials status` との整合も崩れる。migrate の契約は
    // 「config.toml からすべての秘密フィールドを除去する」と一貫させる。
    let toml_keys: [&str; 3] = ["token", "session_key", "password"];
    let mode = prompt_disposal()?;
    let updated = remove_fields(&original, &toml_keys);

    match mode {
        DisposalMode::Remove => {
            if let Err(e) = atomic_replace(&path, updated.as_bytes()) {
                rollback_store(store, &written);
                return Err(SplunkError::Config(format!(
                    "failed to update {}: {}. Credential store entries rolled back.",
                    canonical.display(),
                    e
                )));
            }
            println!("Removed migrated secret lines from {}", canonical.display());
            println!();
            println!("Done. The plaintext secret(s) no longer exist on disk.");
        }
        DisposalMode::KeepBackup => {
            let backup = backup_path(&path);
            if let Err(e) = write_secret_file(&backup, original.as_bytes(), true) {
                rollback_store(store, &written);
                return Err(SplunkError::Config(format!(
                    "failed to write backup {}: {}. Credential store entries rolled back.",
                    backup.display(),
                    e
                )));
            }
            if let Err(e) = atomic_replace(&path, updated.as_bytes()) {
                let _ = fs::remove_file(&backup);
                rollback_store(store, &written);
                return Err(SplunkError::Config(format!(
                    "failed to update {}: {}. Credential store entries rolled back.",
                    canonical.display(),
                    e
                )));
            }
            println!(
                "Removed migrated secret lines from {} (backup at {})",
                canonical.display(),
                backup.display()
            );
            println!();
            println!(
                "WARNING: {} still contains the plaintext secret(s).",
                backup.display()
            );
            println!("This file defeats the purpose of moving secrets to the Keychain.");
            println!("Delete it as soon as you have confirmed the new setup works:");
            println!("  rm {}", backup.display());
        }
    }

    Ok(())
}

fn rollback_store(store: &dyn CredentialStore, keys: &[&str]) {
    for k in keys {
        if let Err(e) = store.delete(k) {
            eprintln!(
                "warning: failed to roll back credential store entry {}: {}",
                k, e
            );
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum DisposalMode {
    /// `*_ = "..."` 行を丸ごと消す。平文コピーを残さない最も安全な選択肢。
    Remove,
    /// 原本を 0o600 バックアップに残す。ユーザーが明示的に選んだときだけ。
    KeepBackup,
}

fn prompt_yes_no(question: &str, default_yes: bool) -> Result<bool> {
    let suffix = if default_yes { "[Y/n]" } else { "[y/N]" };
    print!("{} {}: ", question, suffix);
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(match answer.trim() {
        "" => default_yes,
        s => matches!(s, "y" | "Y" | "yes" | "Yes" | "YES"),
    })
}

fn prompt_disposal() -> Result<DisposalMode> {
    if prompt_yes_no(
        "Remove the plaintext secret lines from config.toml? \
         (Recommended. Choosing 'no' keeps a 0600 backup of the original on disk.)",
        true,
    )? {
        Ok(DisposalMode::Remove)
    } else {
        Ok(DisposalMode::KeepBackup)
    }
}

fn write_secret_file(path: &Path, bytes: &[u8], exclusive: bool) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).mode(SECRET_FILE_MODE);
    if exclusive {
        opts.create_new(true);
    } else {
        opts.create(true).truncate(true);
    }
    let mut f: File = opts
        .open(path)
        .map_err(|e| SplunkError::Config(format!("open {}: {}", path.display(), e)))?;
    f.write_all(bytes)
        .map_err(|e| SplunkError::Config(format!("write {}: {}", path.display(), e)))?;
    // 念押し。ネットワーク FS だと open 時 mode が反映されないことがある。
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(SECRET_FILE_MODE));
    Ok(())
}

/// `path` を `bytes` で atomic に置き換える。同ディレクトリに 0o600 の tempfile を作り
/// `rename` で差し替える。結果ファイルの mode は 0o600 になる。
fn atomic_replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp.{}", ts));
    let tmp = dir.join(name);

    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(SECRET_FILE_MODE)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all().ok();
    }
    let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(SECRET_FILE_MODE));
    fs::rename(&tmp, path).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })
}

fn find_config_toml() -> Option<PathBuf> {
    config_search_paths().into_iter().find(|p| p.is_file())
}

fn backup_path(p: &Path) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut name = p.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".bak.{}", ts));
    p.with_file_name(name)
}

/// 機密フィールドの走査結果。
#[derive(Debug, PartialEq, Eq)]
enum FieldScan {
    /// フィールドが無いか、空の basic string。
    Absent,
    /// `key = "..."` 形式で値が取れた。
    Present(String),
    /// 書き換えを拒否する形式（literal / multiline / escaped quote など）。
    Unsupported(&'static str),
}

/// config.toml を行単位で走査して `key` の値を取り出す。
/// TOML 往復パースを避けるのは、ユーザーのコメントや順序を保つため。
fn extract_field(content: &str, key: &str) -> FieldScan {
    for line in content.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix(key) else {
            continue;
        };
        // 単語境界チェック。`token` の先頭一致で `token_other` を拾わないように、
        // 直後が空白か `=` でなければスキップする。
        let next_char = rest.chars().next();
        match next_char {
            Some(c) if c == '=' || c.is_whitespace() => {}
            _ => continue,
        }
        let after_key = rest.trim_start();
        if !after_key.starts_with('=') {
            continue;
        }
        let value_part = after_key[1..].trim_start();

        if value_part.starts_with("\"\"\"") {
            return FieldScan::Unsupported("multi-line basic string (\"\"\"...\"\"\")");
        }
        if value_part.starts_with("'''") {
            return FieldScan::Unsupported("multi-line literal string ('''...''')");
        }
        if value_part.starts_with('\'') {
            return FieldScan::Unsupported("literal string ('...')");
        }
        if let Some(rest) = value_part.strip_prefix('"') {
            if rest.contains("\\\"") {
                return FieldScan::Unsupported("basic string with escaped quotes");
            }
            return match rest.find('"') {
                Some(0) => FieldScan::Absent,
                Some(end) => FieldScan::Present(rest[..end].to_string()),
                None => FieldScan::Unsupported("unterminated basic string"),
            };
        }
        return FieldScan::Unsupported("unrecognized value form");
    }
    FieldScan::Absent
}

/// `keys` に含まれる行を丸ごと消す。順序やコメントは保つ。
/// `token` / `session_key` / `password` など、先頭一致だけではなく単語境界まで見る。
fn remove_fields(content: &str, keys: &[&str]) -> String {
    let mut out = String::with_capacity(content.len());
    'lines: for line in content.lines() {
        let trimmed = line.trim_start();
        for k in keys {
            if let Some(rest) = trimmed.strip_prefix(*k) {
                let next_char = rest.chars().next();
                let boundary = matches!(next_char, Some(c) if c == '=' || c.is_whitespace());
                if !boundary {
                    continue;
                }
                let after = rest.trim_start();
                if after.starts_with('=') {
                    continue 'lines; // 行を skip
                }
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_token() {
        let s = r#"
base_url = "https://x"
token = "abc123"
"#;
        assert_eq!(
            extract_field(s, "token"),
            FieldScan::Present("abc123".to_string())
        );
    }

    #[test]
    fn extract_session_key() {
        let s = "session_key = \"sk123\"\n";
        assert_eq!(
            extract_field(s, "session_key"),
            FieldScan::Present("sk123".to_string())
        );
    }

    #[test]
    fn extract_absent_when_missing() {
        let s = "base_url = \"https://x\"\n";
        assert_eq!(extract_field(s, "token"), FieldScan::Absent);
    }

    #[test]
    fn extract_absent_for_empty_basic_string() {
        assert_eq!(extract_field("token = \"\"\n", "token"), FieldScan::Absent);
    }

    #[test]
    fn extract_rejects_literal_string() {
        let s = "token = 'abc'\n";
        assert!(matches!(
            extract_field(s, "token"),
            FieldScan::Unsupported(_)
        ));
    }

    #[test]
    fn extract_rejects_multiline_basic() {
        let s = "token = \"\"\"abc\"\"\"\n";
        assert!(matches!(
            extract_field(s, "token"),
            FieldScan::Unsupported(_)
        ));
    }

    #[test]
    fn extract_ignores_similar_keys() {
        // `token_other` を `token` として拾わないこと。
        let s = "token_other = \"x\"\n";
        assert_eq!(extract_field(s, "token"), FieldScan::Absent);
    }

    #[test]
    fn remove_drops_only_target_lines() {
        let s = r#"# comment
base_url = "https://x"
token = "abc123"
session_key = "sk"
password = "pw"
default_app = "search"
"#;
        let out = remove_fields(s, &["token", "session_key", "password"]);
        assert!(!out.contains("abc123"));
        assert!(!out.contains("sk"));
        assert!(!out.contains("pw"));
        // `password` 行は丸ごと消えるので "password" という単語も残らない
        assert!(!out.contains("password"));
        assert!(out.contains("# comment"));
        assert!(out.contains("base_url = \"https://x\""));
        assert!(out.contains("default_app = \"search\""));
    }

    #[test]
    fn remove_handles_indented_key() {
        let s = "  token = \"x\"\nother = 1\n";
        let out = remove_fields(s, &["token"]);
        assert_eq!(out, "other = 1\n");
    }

    #[test]
    fn remove_leaves_similar_keys_alone() {
        let s = "token_other = \"x\"\n";
        let out = remove_fields(s, &["token"]);
        assert_eq!(out, "token_other = \"x\"\n");
    }

    #[test]
    fn atomic_replace_writes_with_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "old\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        atomic_replace(&path, b"new\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new\n");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn write_secret_file_creates_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup");
        write_secret_file(&path, b"secret\n", true).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn write_secret_file_exclusive_refuses_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup");
        std::fs::write(&path, b"existing").unwrap();
        let err = write_secret_file(&path, b"new", true).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("open"), "unexpected error: {}", msg);
    }
}

use crate::error::{Result, SplunkError};
use std::io::Read;

/// `@path` / `@-` で読み込めるバイト数の上限。
/// SPL や JSON ペイロードはこれより十分に小さいので、超過は誤指定とみなす。
pub const READ_DATA_ARG_MAX_BYTES: u64 = 1 << 20;

/// `@path` なら `path` ファイル内容を返す。`@-` なら stdin を読み込む。
/// それ以外の文字列はそのまま返す。
/// 入力が `READ_DATA_ARG_MAX_BYTES` を超える場合は `SplunkError::Config` を返す。
pub fn read_data_arg(value: &str) -> Result<String> {
    read_data_arg_with_limit(value, READ_DATA_ARG_MAX_BYTES)
}

fn read_data_arg_with_limit(value: &str, limit: u64) -> Result<String> {
    if value == "@-" {
        let mut buf = String::new();
        // limit + 1 まで読んで、超えたらエラーにする。
        let mut handle = std::io::stdin().lock().take(limit + 1);
        handle.read_to_string(&mut buf)?;
        if buf.len() as u64 > limit {
            return Err(SplunkError::Config(format!(
                "stdin input exceeds {} bytes (configured limit)",
                limit
            )));
        }
        return Ok(buf);
    }
    if let Some(path) = value.strip_prefix('@') {
        let metadata = std::fs::metadata(path)?;
        if metadata.len() > limit {
            return Err(SplunkError::Config(format!(
                "{} is {} bytes; exceeds {}-byte limit",
                path,
                metadata.len(),
                limit
            )));
        }
        return Ok(std::fs::read_to_string(path)?);
    }
    Ok(value.to_string())
}

/// 先頭から最大 `max` 文字を返す（char 境界で安全に切る）。
///
/// `String::truncate` / `str::truncate` はバイト位置が char 境界でないと
/// panic する。HTTP エラー本文を短く出すような用途で、マルチバイト文字や
/// `String::from_utf8_lossy` 由来の U+FFFD を含む文字列を安全に切り詰める。
pub fn truncate_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// `key=value` 形式の文字列を `(key, value)` に分解する。
pub fn parse_kv(s: &str) -> Result<(String, String)> {
    let (k, v) = s
        .split_once('=')
        .ok_or_else(|| SplunkError::Config(format!("expected key=value, got `{}`", s)))?;
    Ok((k.to_string(), v.to_string()))
}

/// 複数の `key=value` を `Vec<(String, String)>` に変換する。
pub fn parse_kv_list(items: &[String]) -> Result<Vec<(String, String)>> {
    items.iter().map(|s| parse_kv(s)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kv_ok() {
        assert_eq!(parse_kv("a=b").unwrap(), ("a".into(), "b".into()));
        assert_eq!(
            parse_kv("search=index=_internal").unwrap(),
            ("search".into(), "index=_internal".into())
        );
    }

    #[test]
    fn parse_kv_err() {
        assert!(parse_kv("novalue").is_err());
    }

    #[test]
    fn truncate_chars_keeps_short_strings() {
        assert_eq!(truncate_chars("hello", 200), "hello");
    }

    #[test]
    fn truncate_chars_limits_by_chars() {
        let s: String = "a".repeat(300);
        assert_eq!(truncate_chars(&s, 200).chars().count(), 200);
    }

    #[test]
    fn truncate_chars_does_not_panic_on_multibyte_boundary() {
        // マルチバイト文字（各 3 バイト）。バイト truncate なら境界で panic するが、
        // char 単位なら安全。100 文字に収め、panic しないことを確認する。
        let s: String = "あ".repeat(300);
        let out = truncate_chars(&s, 100);
        assert_eq!(out.chars().count(), 100);
        assert!(out.chars().all(|c| c == 'あ'));
    }

    #[test]
    fn truncate_chars_handles_replacement_char() {
        // from_utf8_lossy が生む U+FFFD（3 バイト）混じりでも安全に切る。
        let raw = b"ok\xff\xfe more text that is long enough to exceed".to_vec();
        let lossy = String::from_utf8_lossy(&raw);
        let out = truncate_chars(&lossy, 5);
        assert_eq!(out.chars().count(), 5);
    }

    #[test]
    fn read_data_arg_literal() {
        assert_eq!(read_data_arg("hello").unwrap(), "hello");
    }

    #[test]
    fn read_data_arg_file_within_limit() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "splunk-cloud-cli-util-test-{}.txt",
            std::process::id()
        ));
        std::fs::write(&path, "hello world").unwrap();
        let arg = format!("@{}", path.display());
        let body = read_data_arg_with_limit(&arg, 1024).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(body, "hello world");
    }

    #[test]
    fn read_data_arg_file_exceeds_limit() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "splunk-cloud-cli-util-test-big-{}.txt",
            std::process::id()
        ));
        std::fs::write(&path, "x".repeat(100)).unwrap();
        let arg = format!("@{}", path.display());
        let err = read_data_arg_with_limit(&arg, 10).expect_err("should refuse");
        std::fs::remove_file(&path).ok();
        let msg = format!("{}", err);
        assert!(msg.contains("exceeds"), "got: {}", msg);
    }
}

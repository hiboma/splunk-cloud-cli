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

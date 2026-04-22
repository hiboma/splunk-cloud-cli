use crate::error::{Result, SplunkError};
use std::io::Read;

/// `@path` なら `path` ファイル内容を返す。`@-` なら stdin を読み込む。
/// それ以外の文字列はそのまま返す。
pub fn read_data_arg(value: &str) -> Result<String> {
    if value == "@-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        return Ok(buf);
    }
    if let Some(path) = value.strip_prefix('@') {
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
}

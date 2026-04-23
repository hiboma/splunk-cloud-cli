use crate::cli::{OutputFormat, SearchCmd};
use crate::client::SplunkClient;
use crate::error::{Result, SplunkError};
use crate::output::print_value;
use crate::util::{parse_kv_list, read_data_arg};
use serde_json::Value;

pub async fn run(cmd: &SearchCmd, client: &SplunkClient, format: OutputFormat) -> Result<()> {
    match cmd {
        SearchCmd::Parse {
            query,
            enable_lookups,
            reload_macros,
        } => {
            let raw = read_data_arg(query)?;
            let spl = normalize_spl(&raw);
            let enable_lookups_str = if *enable_lookups { "true" } else { "false" };
            let reload_macros_str = if *reload_macros { "true" } else { "false" };
            let form: Vec<(&str, &str)> = vec![
                ("q", spl.as_str()),
                ("parse_only", "true"),
                ("enable_lookups", enable_lookups_str),
                ("reload_macros", reload_macros_str),
            ];
            let (status, value) = client
                .post_form_allow_error("/services/search/parser", &form)
                .await?;
            print_value(&value, format)?;
            // 構文エラー時、parser は messages[].type=FATAL を返す。
            // 通常は HTTP 400 と FATAL が同時に来るが、片方だけでも失敗扱いにする。
            if let Some(msg) = first_fatal_message(&value) {
                return Err(SplunkError::Api(format!("SPL parse error: {}", msg)));
            }
            // セーフティネット: parser が FATAL を返さずに 4xx を返す未知応答の保険。
            if !status.is_success() {
                return Err(SplunkError::Api(format!(
                    "SPL parse failed with HTTP {}",
                    status
                )));
            }
        }
        SearchCmd::Run {
            query,
            earliest,
            latest,
            count,
        } => {
            let spl = normalize_spl(query);
            let count_str = count.to_string();
            let form: Vec<(&str, &str)> = vec![
                ("search", spl.as_str()),
                ("earliest_time", earliest.as_str()),
                ("latest_time", latest.as_str()),
                ("exec_mode", "oneshot"),
                ("count", count_str.as_str()),
                ("output_mode", "json"),
            ];
            let value = client.post_form("/services/search/jobs", &form).await?;
            print_value(&value, format)?;
        }
        SearchCmd::Export {
            query,
            earliest,
            latest,
        } => {
            let spl = normalize_spl(query);
            let query: Vec<(&str, &str)> = vec![
                ("search", spl.as_str()),
                ("earliest_time", earliest.as_str()),
                ("latest_time", latest.as_str()),
                ("output_mode", "json"),
            ];
            client
                .get_stream_lines("/services/search/jobs/export", &query, |line| {
                    println!("{}", line);
                    Ok(())
                })
                .await?;
        }
        SearchCmd::JobsLs => {
            let value = client.get("/services/search/jobs", &[]).await?;
            print_value(&value, format)?;
        }
        SearchCmd::JobsGet { sid } => {
            let path = format!("/services/search/jobs/{}", SplunkClient::encode(sid));
            let value = client.get(&path, &[]).await?;
            print_value(&value, format)?;
        }
        SearchCmd::JobsRm { sid } => {
            let path = format!("/services/search/jobs/{}", SplunkClient::encode(sid));
            let value = client.delete(&path).await?;
            print_value(&value, format)?;
        }
        SearchCmd::Results { sid, offset, count } => {
            let path = format!(
                "/services/search/jobs/{}/results",
                SplunkClient::encode(sid)
            );
            let offset = offset.to_string();
            let count = count.to_string();
            let value = client
                .get(&path, &[("offset", &offset), ("count", &count)])
                .await?;
            print_value(&value, format)?;
        }
        SearchCmd::Events { sid, offset, count } => {
            let path = format!("/services/search/jobs/{}/events", SplunkClient::encode(sid));
            let offset = offset.to_string();
            let count = count.to_string();
            let value = client
                .get(&path, &[("offset", &offset), ("count", &count)])
                .await?;
            print_value(&value, format)?;
        }
        SearchCmd::Summary { sid } => {
            let path = format!(
                "/services/search/jobs/{}/summary",
                SplunkClient::encode(sid)
            );
            let value = client.get(&path, &[]).await?;
            print_value(&value, format)?;
        }
        SearchCmd::Control { sid, action, param } => {
            let path = format!(
                "/services/search/jobs/{}/control",
                SplunkClient::encode(sid)
            );
            let extras = parse_kv_list(param)?;
            let mut form: Vec<(&str, &str)> = vec![("action", action.as_str())];
            for (k, v) in extras.iter() {
                form.push((k.as_str(), v.as_str()));
            }
            let value = client.post_form(&path, &form).await?;
            print_value(&value, format)?;
        }
    }
    Ok(())
}

/// SPL の先頭に `search ` / `|` が無い場合は `search ` を補う。
fn normalize_spl(q: &str) -> String {
    let trimmed = q.trim_start();
    if trimmed.starts_with('|') || trimmed.starts_with("search ") || trimmed.starts_with("search\t")
    {
        q.to_string()
    } else {
        format!("search {}", q)
    }
}

/// `messages[]` の中から FATAL/ERROR を 1 件取り出して文字列化する。
/// Splunk parser は構文エラーでも HTTP 200 を返すことがあるため必須。
fn first_fatal_message(value: &Value) -> Option<String> {
    let messages = value.get("messages")?.as_array()?;
    for m in messages {
        let ty = m.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if ty.eq_ignore_ascii_case("FATAL") || ty.eq_ignore_ascii_case("ERROR") {
            let text = m
                .get("text")
                .and_then(|v| v.as_str())
                .unwrap_or("(no text)");
            return Some(format!("[{}] {}", ty, text));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalize_adds_search_prefix() {
        assert_eq!(normalize_spl("index=_internal"), "search index=_internal");
    }

    #[test]
    fn normalize_keeps_explicit_search() {
        assert_eq!(
            normalize_spl("search index=_internal"),
            "search index=_internal"
        );
    }

    #[test]
    fn normalize_keeps_pipe_command() {
        assert_eq!(normalize_spl("| tstats count"), "| tstats count");
    }

    #[test]
    fn fatal_message_detected() {
        let v = json!({
            "messages": [
                {"type": "FATAL", "text": "Unknown search command 'bizzbuzz'"}
            ]
        });
        let m = first_fatal_message(&v).expect("should detect FATAL");
        assert!(m.contains("FATAL"));
        assert!(m.contains("bizzbuzz"));
    }

    #[test]
    fn fatal_message_absent_on_clean_response() {
        let v = json!({
            "remoteSearch": "search index=_internal",
            "messages": []
        });
        assert!(first_fatal_message(&v).is_none());
    }

    #[test]
    fn fatal_message_ignores_info_level() {
        let v = json!({
            "messages": [
                {"type": "INFO", "text": "ok"},
                {"type": "WARN", "text": "deprecated syntax"}
            ]
        });
        assert!(first_fatal_message(&v).is_none());
    }
}

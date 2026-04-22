use crate::cli::{OutputFormat, SearchCmd};
use crate::client::SplunkClient;
use crate::error::Result;
use crate::output::print_value;
use crate::util::parse_kv_list;

pub async fn run(cmd: &SearchCmd, client: &SplunkClient, format: OutputFormat) -> Result<()> {
    match cmd {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}

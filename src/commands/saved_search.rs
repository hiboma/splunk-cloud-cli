use crate::cli::{OutputFormat, SavedSearchCmd};
use crate::client::SplunkClient;
use crate::error::Result;
use crate::output::print_value;
use crate::util::parse_kv_list;

pub async fn run(cmd: &SavedSearchCmd, client: &SplunkClient, format: OutputFormat) -> Result<()> {
    let base = client.ns_path(None, None, "saved/searches");
    match cmd {
        SavedSearchCmd::List { count } => {
            let count = count.to_string();
            let value = client.get(&base, &[("count", &count)]).await?;
            print_value(&value, format)?;
        }
        SavedSearchCmd::Get { name } => {
            let path = format!("{}/{}", base, SplunkClient::encode(name));
            let value = client.get(&path, &[]).await?;
            print_value(&value, format)?;
        }
        SavedSearchCmd::Create {
            name,
            search,
            param,
        } => {
            let extras = parse_kv_list(param)?;
            let mut form: Vec<(&str, &str)> =
                vec![("name", name.as_str()), ("search", search.as_str())];
            for (k, v) in extras.iter() {
                form.push((k.as_str(), v.as_str()));
            }
            let value = client.post_form(&base, &form).await?;
            print_value(&value, format)?;
        }
        SavedSearchCmd::Update { name, param } => {
            let path = format!("{}/{}", base, SplunkClient::encode(name));
            let extras = parse_kv_list(param)?;
            let form: Vec<(&str, &str)> = extras
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            let value = client.post_form(&path, &form).await?;
            print_value(&value, format)?;
        }
        SavedSearchCmd::Delete { name } => {
            let path = format!("{}/{}", base, SplunkClient::encode(name));
            let value = client.delete(&path).await?;
            print_value(&value, format)?;
        }
        SavedSearchCmd::Dispatch { name, param } => {
            let path = format!("{}/{}/dispatch", base, SplunkClient::encode(name));
            let extras = parse_kv_list(param)?;
            let form: Vec<(&str, &str)> = extras
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            let value = client.post_form(&path, &form).await?;
            print_value(&value, format)?;
        }
        SavedSearchCmd::History { name } => {
            let path = format!("{}/{}/history", base, SplunkClient::encode(name));
            let value = client.get(&path, &[]).await?;
            print_value(&value, format)?;
        }
        SavedSearchCmd::Acl { name } => {
            let path = format!("{}/{}/acl", base, SplunkClient::encode(name));
            let value = client.get(&path, &[]).await?;
            print_value(&value, format)?;
        }
    }
    Ok(())
}

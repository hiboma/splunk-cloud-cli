use crate::cli::{KvstoreCmd, OutputFormat};
use crate::client::SplunkClient;
use crate::error::{Result, SplunkError};
use crate::output::print_value;
use crate::util::{parse_kv_list, read_data_arg};

pub async fn run(cmd: &KvstoreCmd, client: &SplunkClient, format: OutputFormat) -> Result<()> {
    let collections_config = client.ns_path(None, None, "storage/collections/config");
    let collections_data = client.ns_path(None, None, "storage/collections/data");
    match cmd {
        KvstoreCmd::CollectionLs => {
            let value = client.get(&collections_config, &[]).await?;
            print_value(&value, format)?;
        }
        KvstoreCmd::CollectionGet { name } => {
            let path = format!("{}/{}", collections_config, SplunkClient::encode(name));
            let value = client.get(&path, &[]).await?;
            print_value(&value, format)?;
        }
        KvstoreCmd::CollectionCreate { name, param } => {
            let extras = parse_kv_list(param)?;
            let mut form: Vec<(&str, &str)> = vec![("name", name.as_str())];
            for (k, v) in extras.iter() {
                form.push((k.as_str(), v.as_str()));
            }
            let value = client.post_form(&collections_config, &form).await?;
            print_value(&value, format)?;
        }
        KvstoreCmd::CollectionRm { name } => {
            let path = format!("{}/{}", collections_config, SplunkClient::encode(name));
            let value = client.delete(&path).await?;
            print_value(&value, format)?;
        }

        KvstoreCmd::DataLs {
            collection,
            query,
            fields,
            limit,
            skip,
            sort,
        } => {
            let path = format!("{}/{}", collections_data, SplunkClient::encode(collection));
            let limit_s = limit.map(|v| v.to_string());
            let skip_s = skip.map(|v| v.to_string());
            let mut q: Vec<(&str, &str)> = Vec::new();
            if let Some(v) = query {
                q.push(("query", v.as_str()));
            }
            if let Some(v) = fields {
                q.push(("fields", v.as_str()));
            }
            if let Some(v) = &limit_s {
                q.push(("limit", v.as_str()));
            }
            if let Some(v) = &skip_s {
                q.push(("skip", v.as_str()));
            }
            if let Some(v) = sort {
                q.push(("sort", v.as_str()));
            }
            let value = client.get(&path, &q).await?;
            print_value(&value, format)?;
        }
        KvstoreCmd::DataGet { collection, key } => {
            let path = format!(
                "{}/{}/{}",
                collections_data,
                SplunkClient::encode(collection),
                SplunkClient::encode(key)
            );
            let value = client.get(&path, &[]).await?;
            print_value(&value, format)?;
        }
        KvstoreCmd::DataInsert { collection, data } => {
            let path = format!("{}/{}", collections_data, SplunkClient::encode(collection));
            let payload = read_data_arg(data)?;
            let json: serde_json::Value = serde_json::from_str(&payload)
                .map_err(|e| SplunkError::Config(format!("invalid JSON: {}", e)))?;
            let value = client.post_json(&path, &json).await?;
            print_value(&value, format)?;
        }
        KvstoreCmd::DataUpdate {
            collection,
            key,
            data,
        } => {
            let path = format!(
                "{}/{}/{}",
                collections_data,
                SplunkClient::encode(collection),
                SplunkClient::encode(key)
            );
            let payload = read_data_arg(data)?;
            let json: serde_json::Value = serde_json::from_str(&payload)
                .map_err(|e| SplunkError::Config(format!("invalid JSON: {}", e)))?;
            let value = client.post_json(&path, &json).await?;
            print_value(&value, format)?;
        }
        KvstoreCmd::DataRm { collection, key } => {
            let path = if let Some(k) = key {
                format!(
                    "{}/{}/{}",
                    collections_data,
                    SplunkClient::encode(collection),
                    SplunkClient::encode(k)
                )
            } else {
                format!("{}/{}", collections_data, SplunkClient::encode(collection))
            };
            let value = client.delete(&path).await?;
            print_value(&value, format)?;
        }
        KvstoreCmd::DataBatchSave { collection, data } => {
            let path = format!(
                "{}/{}/batch_save",
                collections_data,
                SplunkClient::encode(collection)
            );
            let payload = read_data_arg(data)?;
            let json: serde_json::Value = serde_json::from_str(&payload)
                .map_err(|e| SplunkError::Config(format!("invalid JSON: {}", e)))?;
            let value = client.post_json(&path, &json).await?;
            print_value(&value, format)?;
        }
    }
    Ok(())
}

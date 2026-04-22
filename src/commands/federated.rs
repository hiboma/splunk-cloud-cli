use crate::cli::{FederatedCmd, OutputFormat};
use crate::client::SplunkClient;
use crate::error::Result;
use crate::output::print_value;
use crate::util::parse_kv_list;

pub async fn run(cmd: &FederatedCmd, client: &SplunkClient, format: OutputFormat) -> Result<()> {
    match cmd {
        FederatedCmd::ProviderLs => {
            let v = client.get("/services/data/federated/provider", &[]).await?;
            print_value(&v, format)?;
        }
        FederatedCmd::ProviderGet { name } => {
            let path = format!(
                "/services/data/federated/provider/{}",
                SplunkClient::encode(name)
            );
            let v = client.get(&path, &[]).await?;
            print_value(&v, format)?;
        }
        FederatedCmd::ProviderCreate { name, param } => {
            let extras = parse_kv_list(param)?;
            let mut form: Vec<(&str, &str)> = vec![("name", name.as_str())];
            for (k, v) in extras.iter() {
                form.push((k.as_str(), v.as_str()));
            }
            let v = client
                .post_form("/services/data/federated/provider", &form)
                .await?;
            print_value(&v, format)?;
        }
        FederatedCmd::ProviderRm { name } => {
            let path = format!(
                "/services/data/federated/provider/{}",
                SplunkClient::encode(name)
            );
            let v = client.delete(&path).await?;
            print_value(&v, format)?;
        }
        FederatedCmd::IndexLs => {
            let v = client.get("/services/data/federated/index", &[]).await?;
            print_value(&v, format)?;
        }
        FederatedCmd::IndexGet { name } => {
            let path = format!(
                "/services/data/federated/index/{}",
                SplunkClient::encode(name)
            );
            let v = client.get(&path, &[]).await?;
            print_value(&v, format)?;
        }
        FederatedCmd::IndexCreate { name, param } => {
            let extras = parse_kv_list(param)?;
            let mut form: Vec<(&str, &str)> = vec![("name", name.as_str())];
            for (k, v) in extras.iter() {
                form.push((k.as_str(), v.as_str()));
            }
            let v = client
                .post_form("/services/data/federated/index", &form)
                .await?;
            print_value(&v, format)?;
        }
        FederatedCmd::IndexRm { name } => {
            let path = format!(
                "/services/data/federated/index/{}",
                SplunkClient::encode(name)
            );
            let v = client.delete(&path).await?;
            print_value(&v, format)?;
        }
        FederatedCmd::Settings => {
            let v = client
                .get("/services/data/federated/settings/general", &[])
                .await?;
            print_value(&v, format)?;
        }
    }
    Ok(())
}

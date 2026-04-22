use crate::cli::{DashboardCmd, OutputFormat};
use crate::client::SplunkClient;
use crate::error::Result;
use crate::output::print_value;
use crate::util::read_data_arg;

pub async fn run(cmd: &DashboardCmd, client: &SplunkClient, format: OutputFormat) -> Result<()> {
    let views = client.ns_path(None, None, "data/ui/views");
    let panels = client.ns_path(None, None, "data/ui/panels");
    match cmd {
        DashboardCmd::List { count } => {
            let count = count.to_string();
            let value = client.get(&views, &[("count", &count)]).await?;
            print_value(&value, format)?;
        }
        DashboardCmd::Get { name } => {
            let path = format!("{}/{}", views, SplunkClient::encode(name));
            let value = client.get(&path, &[]).await?;
            print_value(&value, format)?;
        }
        DashboardCmd::Create { name, data } => {
            let payload = read_data_arg(data)?;
            let form: Vec<(&str, &str)> =
                vec![("name", name.as_str()), ("eai:data", payload.as_str())];
            let value = client.post_form(&views, &form).await?;
            print_value(&value, format)?;
        }
        DashboardCmd::Update {
            name,
            data,
            changelog,
        } => {
            let path = format!("{}/{}", views, SplunkClient::encode(name));
            let payload = read_data_arg(data)?;
            let mut form: Vec<(&str, &str)> = vec![("eai:data", payload.as_str())];
            if let Some(cl) = changelog {
                form.push(("eai:changelog", cl.as_str()));
            }
            let value = client.post_form(&path, &form).await?;
            print_value(&value, format)?;
        }
        DashboardCmd::Delete { name } => {
            let path = format!("{}/{}", views, SplunkClient::encode(name));
            let value = client.delete(&path).await?;
            print_value(&value, format)?;
        }
        DashboardCmd::History { name } => {
            let path = format!("{}/{}/history", views, SplunkClient::encode(name));
            let value = client.get(&path, &[]).await?;
            print_value(&value, format)?;
        }
        DashboardCmd::Revision { name, revision_id } => {
            let path = format!("{}/{}/revision", views, SplunkClient::encode(name));
            let value = client.get(&path, &[("revision_id", revision_id)]).await?;
            print_value(&value, format)?;
        }
        DashboardCmd::PanelLs => {
            let value = client.get(&panels, &[]).await?;
            print_value(&value, format)?;
        }
        DashboardCmd::PanelGet { name } => {
            let path = format!("{}/{}", panels, SplunkClient::encode(name));
            let value = client.get(&path, &[]).await?;
            print_value(&value, format)?;
        }
    }
    Ok(())
}

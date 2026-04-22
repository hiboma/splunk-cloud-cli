use crate::cli::{AlertCmd, OutputFormat};
use crate::client::SplunkClient;
use crate::error::Result;
use crate::output::print_value;

pub async fn run(cmd: &AlertCmd, client: &SplunkClient, format: OutputFormat) -> Result<()> {
    match cmd {
        AlertCmd::ActionsLs => {
            let v = client.get("/services/alerts/alert_actions", &[]).await?;
            print_value(&v, format)?;
        }
        AlertCmd::FiredLs => {
            let v = client.get("/services/alerts/fired_alerts", &[]).await?;
            print_value(&v, format)?;
        }
        AlertCmd::FiredRm { name } => {
            let path = format!(
                "/services/alerts/fired_alerts/{}",
                SplunkClient::encode(name)
            );
            let v = client.delete(&path).await?;
            print_value(&v, format)?;
        }
    }
    Ok(())
}

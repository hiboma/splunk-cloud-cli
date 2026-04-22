use crate::cli::{MetricsCmd, OutputFormat};
use crate::client::SplunkClient;
use crate::error::Result;
use crate::output::print_value;

pub async fn run(cmd: &MetricsCmd, client: &SplunkClient, format: OutputFormat) -> Result<()> {
    match cmd {
        MetricsCmd::Names {
            earliest,
            latest,
            filter,
        } => {
            let mut q: Vec<(&str, &str)> =
                vec![("earliest", earliest.as_str()), ("latest", latest.as_str())];
            if let Some(f) = filter {
                q.push(("filter", f.as_str()));
            }
            let v = client
                .get("/services/catalog/metricstore/metrics", &q)
                .await?;
            print_value(&v, format)?;
        }
        MetricsCmd::Dimensions {
            metric_name,
            earliest,
            latest,
            filter,
        } => {
            let mut q: Vec<(&str, &str)> = vec![
                ("metric_name", metric_name.as_str()),
                ("earliest", earliest.as_str()),
                ("latest", latest.as_str()),
            ];
            if let Some(f) = filter {
                q.push(("filter", f.as_str()));
            }
            let v = client
                .get("/services/catalog/metricstore/dimensions", &q)
                .await?;
            print_value(&v, format)?;
        }
        MetricsCmd::RollupLs => {
            let v = client
                .get("/services/catalog/metricstore/rollup", &[])
                .await?;
            print_value(&v, format)?;
        }
    }
    Ok(())
}

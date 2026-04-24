use crate::cli::{IndexCmd, OutputFormat};
use crate::client::SplunkClient;
use crate::error::Result;
use crate::output::print_value;

pub async fn run(cmd: &IndexCmd, client: &SplunkClient, format: OutputFormat) -> Result<()> {
    match cmd {
        IndexCmd::Ls { count, summarize } => {
            // Splunkd `count=0` means "all entries" (REST API spec).
            let count_s = count.to_string();
            let mut q: Vec<(&str, &str)> = vec![("count", count_s.as_str())];
            if *summarize {
                q.push(("summarize", "true"));
            }
            let v = client.get("/services/data/indexes", &q).await?;
            print_value(&v, format)?;
        }
        IndexCmd::Get { name } => {
            let path = format!("/services/data/indexes/{}", SplunkClient::encode(name));
            let v = client.get(&path, &[]).await?;
            print_value(&v, format)?;
        }
    }
    Ok(())
}

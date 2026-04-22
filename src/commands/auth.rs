use crate::cli::{AuthCmd, OutputFormat};
use crate::client::SplunkClient;
use crate::error::Result;
use crate::output::print_value;

pub async fn run(cmd: &AuthCmd, client: &SplunkClient, format: OutputFormat) -> Result<()> {
    match cmd {
        AuthCmd::Whoami => {
            // Cloud では `/services/authentication/current-context` が access-endpoints に
            // 明示掲載されていないため、まず叩いて失敗したら `/services/authentication/users` に
            // フォールバックするのが堅いが、まずは plan.md の初期リスト通りに実装する。
            let value = client
                .get("/services/authentication/current-context", &[])
                .await?;
            print_value(&value, format)?;
        }
    }
    Ok(())
}

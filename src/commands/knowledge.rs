use crate::cli::{KnowledgeCmd, OutputFormat};
use crate::client::SplunkClient;
use crate::error::Result;
use crate::output::print_value;

pub async fn run(cmd: &KnowledgeCmd, client: &SplunkClient, format: OutputFormat) -> Result<()> {
    match cmd {
        KnowledgeCmd::LookupLs => get_ns(client, "data/lookup-table-files", format).await,
        KnowledgeCmd::LookupGet { name } => {
            get_ns_one(client, "data/lookup-table-files", name, format).await
        }
        KnowledgeCmd::LookupRm { name } => {
            delete_ns_one(client, "data/lookup-table-files", name, format).await
        }

        KnowledgeCmd::CalcfieldsLs => get_ns(client, "data/props/calcfields", format).await,
        KnowledgeCmd::ExtractionsLs => get_ns(client, "data/props/extractions", format).await,
        KnowledgeCmd::FieldaliasesLs => get_ns(client, "data/props/fieldaliases", format).await,

        KnowledgeCmd::TransformsLookupsLs => {
            get_ns(client, "data/transforms/lookups", format).await
        }
        KnowledgeCmd::TransformsExtractionsLs => {
            get_ns(client, "data/transforms/extractions", format).await
        }

        KnowledgeCmd::MacrosLs => get_ns(client, "configs/conf-macros", format).await,
        KnowledgeCmd::MacrosGet { name } => {
            get_ns_one(client, "configs/conf-macros", name, format).await
        }

        KnowledgeCmd::TagsLs => get_ns(client, "search/tags", format).await,

        KnowledgeCmd::EventtypesLs => get_ns(client, "saved/eventtypes", format).await,
        KnowledgeCmd::EventtypesGet { name } => {
            get_ns_one(client, "saved/eventtypes", name, format).await
        }

        KnowledgeCmd::DatamodelLs => get_ns(client, "datamodel/model", format).await,
        KnowledgeCmd::DatamodelGet { name } => {
            get_ns_one(client, "datamodel/model", name, format).await
        }
    }
}

async fn get_ns(client: &SplunkClient, suffix: &str, format: OutputFormat) -> Result<()> {
    let path = client.ns_path(None, None, suffix);
    let value = client.get(&path, &[]).await?;
    print_value(&value, format)
}

async fn get_ns_one(
    client: &SplunkClient,
    suffix: &str,
    name: &str,
    format: OutputFormat,
) -> Result<()> {
    let base = client.ns_path(None, None, suffix);
    let path = format!("{}/{}", base, SplunkClient::encode(name));
    let value = client.get(&path, &[]).await?;
    print_value(&value, format)
}

async fn delete_ns_one(
    client: &SplunkClient,
    suffix: &str,
    name: &str,
    format: OutputFormat,
) -> Result<()> {
    let base = client.ns_path(None, None, suffix);
    let path = format!("{}/{}", base, SplunkClient::encode(name));
    let value = client.delete(&path).await?;
    print_value(&value, format)
}

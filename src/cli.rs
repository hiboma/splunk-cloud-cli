use clap::{Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Pretty,
    Json,
    Yaml,
    Csv,
}

#[derive(Parser, Debug)]
#[command(
    name = "splunk-cloud-cli",
    about = "CLI for Splunk Cloud Platform REST API (Victoria Experience)",
    version,
    propagate_version = true,
    long_about = "CLI for Splunk Cloud Platform REST API (Victoria Experience).\n\n\
Credentials are never accepted via command-line flags (which would leak through shell history and `ps`).\n\
They come from environment variables OR the config file at:\n\
  ./.splunk-cloud-cli.toml\n\
  $XDG_CONFIG_HOME/splunk-cloud-cli/config.toml  (default: ~/.config/splunk-cloud-cli/config.toml)\n\n\
Secrets (token / session_key / password) can also live in the OS credential store\n\
(macOS Keychain). Priority: env var > credential store > config file.\n\
Use `splunk-cloud-cli credentials set <field>` to store a secret, or\n\
`splunk-cloud-cli credentials migrate` to move secrets out of config.toml.\n\n\
Environment variables always override the config file:\n\
  SPLUNK_BASE_URL        required (or `base_url`)\n\
  SPLUNK_TOKEN           one of these is required (or `token` / `session_key` /\n\
  SPLUNK_SESSION_KEY      (`username` + `password`))\n\
  SPLUNK_USERNAME + SPLUNK_PASSWORD\n\
  SPLUNK_APP             optional, default: search\n\
  SPLUNK_USER            optional, default: nobody"
)]
pub struct Cli {
    /// Default app for `servicesNS/{user}/{app}/...` paths (default: "search").
    /// Use `-` as a wildcard to search across all apps (e.g. `--app -`).
    /// Env: SPLUNK_APP.
    #[arg(long, env = "SPLUNK_APP", hide_env = true, global = true)]
    pub app: Option<String>,

    /// Default user for `servicesNS/{user}/{app}/...` paths (default: "nobody").
    /// Use `-` as a wildcard to include other users' objects (e.g. `--user -`).
    /// Env: SPLUNK_USER.
    #[arg(long, env = "SPLUNK_USER", hide_env = true, global = true)]
    pub user: Option<String>,

    /// Output format. When omitted, the value from the config file is used
    /// (default: pretty).
    #[arg(long, short = 'f', value_enum, global = true)]
    pub format: Option<OutputFormat>,

    /// Print HTTP request/response details to stderr for troubleshooting.
    /// Secrets are redacted (Authorization header shows length only).
    /// Also toggled by SPLUNK_DEBUG=1.
    #[arg(
        long,
        short = 'd',
        env = "SPLUNK_DEBUG",
        hide_env = true,
        global = true
    )]
    pub debug: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Authentication (whoami).
    #[command(subcommand)]
    Auth(AuthCmd),

    /// Search jobs (run, export, jobs-ls, results, ...).
    #[command(subcommand)]
    Search(SearchCmd),

    /// Saved searches (CRUD, dispatch, history, acl).
    #[command(name = "saved-search", subcommand)]
    SavedSearch(SavedSearchCmd),

    /// Dashboards (`data/ui/views`) and panels.
    #[command(subcommand)]
    Dashboard(DashboardCmd),

    /// KV Store collections and data.
    #[command(subcommand)]
    Kvstore(KvstoreCmd),

    /// Knowledge objects (lookup / props / transforms / macros / tags / eventtypes / datamodel).
    #[command(subcommand)]
    Knowledge(KnowledgeCmd),

    /// Federated Search (provider / index / settings).
    #[command(subcommand)]
    Federated(FederatedCmd),

    /// Data indexes (read-only; write belongs to ACS CLI).
    #[command(subcommand)]
    Index(IndexCmd),

    /// Metrics Catalog (metrics / dimensions / rollup).
    #[command(subcommand)]
    Metrics(MetricsCmd),

    /// Alert actions and fired alerts.
    #[command(subcommand)]
    Alert(AlertCmd),

    /// Manage stored credentials (macOS Keychain).
    ///
    /// Secrets are stored in the login keychain under
    /// `service="dev.splunk-cloud-cli"`. Inspect or delete via
    /// Keychain Access.app or `security find-generic-password -s dev.splunk-cloud-cli`.
    /// See README for the full credential resolution order and migration steps.
    #[command(subcommand)]
    Credentials(CredentialsCmd),

    /// Generate shell completion script.
    Completion {
        #[arg(value_enum)]
        shell: Shell,
    },
}

/// `credentials` サブコマンド。値は store の外へは出さない（`get` は用意しない）。
#[derive(Subcommand, Debug)]
pub enum CredentialsCmd {
    /// Store a credential in the OS credential store (e.g. macOS Keychain).
    Set {
        #[arg(value_enum)]
        field: CredentialField,
        /// Read the value from stdin instead of prompting interactively.
        /// Useful for CI / automation. The value must be a single line.
        #[arg(long)]
        stdin: bool,
    },
    /// Delete a credential from the OS credential store.
    Delete {
        #[arg(value_enum)]
        field: CredentialField,
    },
    /// Show whether each credential is stored. Values are never printed.
    Status,
    /// Migrate `token` / `session_key` / `password` from config.toml into the OS credential store.
    Migrate {
        /// Show what would be done without modifying anything.
        #[arg(long)]
        dry_run: bool,
    },
}

/// `credentials` が対象とする機密フィールドの列挙。
///
/// `username` / `base_url` は機密ではなく `config.toml` に置けばよいため対象外。
#[derive(Copy, Clone, Debug, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum CredentialField {
    /// Bearer token（`Authorization: Bearer <token>`）。
    Token,
    /// Splunk session key（`Authorization: Splunk <key>`）。
    SessionKey,
    /// Basic 認証パスワード。
    Password,
}

impl CredentialField {
    /// 対応する store 側のキー。`credential_store` 側の定数とそろえる。
    pub fn key(self) -> &'static str {
        match self {
            CredentialField::Token => crate::config::credential_store::KEY_TOKEN,
            CredentialField::SessionKey => crate::config::credential_store::KEY_SESSION_KEY,
            CredentialField::Password => crate::config::credential_store::KEY_PASSWORD,
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum AuthCmd {
    /// Show current authentication context via `/services/authentication/current-context`.
    Whoami,
}

#[derive(Subcommand, Debug)]
pub enum SearchCmd {
    /// Validate SPL syntax via `/services/search/parser` (no job is created).
    /// Exits non-zero when the parser returns a FATAL message.
    Parse {
        /// SPL query. `@path` reads from a file, `@-` reads from stdin.
        #[arg(long)]
        query: String,
        /// Resolve lookup tables during parsing (slower; off by default).
        #[arg(long)]
        enable_lookups: bool,
        /// Force a reload of macros before parsing.
        #[arg(long)]
        reload_macros: bool,
    },

    /// Run SPL in oneshot mode and print the results.
    Run {
        /// SPL query (a leading `search ` is added automatically when missing).
        #[arg(long)]
        query: String,
        /// earliest_time (e.g. `-15m`, `2026-04-21T00:00:00`).
        #[arg(long, default_value = "-15m")]
        earliest: String,
        /// latest_time.
        #[arg(long, default_value = "now")]
        latest: String,
        /// Maximum rows to return.
        #[arg(long, default_value_t = 100)]
        count: u64,
    },

    /// Stream `search/jobs/export` (chunked JSON Lines to stdout).
    Export {
        #[arg(long)]
        query: String,
        #[arg(long, default_value = "-15m")]
        earliest: String,
        #[arg(long, default_value = "now")]
        latest: String,
    },

    /// List search jobs.
    #[command(name = "jobs-ls")]
    JobsLs,

    /// Get a search job by SID.
    #[command(name = "jobs-get")]
    JobsGet { sid: String },

    /// Delete a search job.
    #[command(name = "jobs-rm")]
    JobsRm { sid: String },

    /// Fetch job results.
    Results {
        sid: String,
        #[arg(long, default_value_t = 0)]
        offset: u64,
        #[arg(long, default_value_t = 100)]
        count: u64,
    },

    /// Fetch raw events for a job.
    Events {
        sid: String,
        #[arg(long, default_value_t = 0)]
        offset: u64,
        #[arg(long, default_value_t = 100)]
        count: u64,
    },

    /// Fetch job field summary.
    Summary { sid: String },

    /// Control a job (pause/unpause/finalize/cancel/touch/setttl/setpriority).
    Control {
        sid: String,
        /// Action name.
        action: String,
        /// Additional key=value parameters (e.g. `--param ttl=600`).
        #[arg(long)]
        param: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum SavedSearchCmd {
    /// List saved searches.
    #[command(name = "ls")]
    List {
        #[arg(long, default_value_t = 30)]
        count: u64,
    },
    /// Get a saved search.
    Get { name: String },
    /// Create a saved search.
    Create {
        name: String,
        #[arg(long)]
        search: String,
        /// Additional key=value parameters.
        #[arg(long)]
        param: Vec<String>,
    },
    /// Update a saved search.
    Update {
        name: String,
        /// key=value parameters (search, cron_schedule, is_scheduled, description, ...).
        #[arg(long)]
        param: Vec<String>,
    },
    /// Delete a saved search.
    #[command(name = "rm")]
    Delete { name: String },
    /// Dispatch a saved search manually.
    Dispatch {
        name: String,
        #[arg(long)]
        param: Vec<String>,
    },
    /// Get dispatch history.
    History { name: String },
    /// Get ACL.
    Acl { name: String },
}

#[derive(Subcommand, Debug)]
pub enum DashboardCmd {
    /// List views.
    #[command(name = "ls")]
    List {
        #[arg(long, default_value_t = 30)]
        count: u64,
    },
    /// Get a view.
    Get { name: String },
    /// Create a view (`--data` accepts literal XML/JSON, `@path`, or `@-` for stdin).
    Create {
        name: String,
        #[arg(long, value_name = "XML_OR_@FILE")]
        data: String,
    },
    /// Update a view.
    Update {
        name: String,
        #[arg(long, value_name = "XML_OR_@FILE")]
        data: String,
        #[arg(long)]
        changelog: Option<String>,
    },
    /// Delete a view.
    #[command(name = "rm")]
    Delete { name: String },
    /// View revision history.
    History { name: String },
    /// Get a specific revision.
    Revision {
        name: String,
        #[arg(long)]
        revision_id: String,
    },
    /// List panels.
    #[command(name = "panel-ls")]
    PanelLs,
    /// Get a panel.
    #[command(name = "panel-get")]
    PanelGet { name: String },
}

#[derive(Subcommand, Debug)]
pub enum KvstoreCmd {
    /// List collections.
    #[command(name = "collection-ls")]
    CollectionLs,
    /// Get a collection config.
    #[command(name = "collection-get")]
    CollectionGet { name: String },
    /// Create a collection (`--param key=value` for extra settings).
    #[command(name = "collection-create")]
    CollectionCreate {
        name: String,
        #[arg(long)]
        param: Vec<String>,
    },
    /// Delete a collection.
    #[command(name = "collection-rm")]
    CollectionRm { name: String },

    /// List documents (all or filtered by query).
    #[command(name = "data-ls")]
    DataLs {
        collection: String,
        #[arg(long)]
        query: Option<String>,
        #[arg(long)]
        fields: Option<String>,
        #[arg(long)]
        limit: Option<u64>,
        #[arg(long)]
        skip: Option<u64>,
        #[arg(long)]
        sort: Option<String>,
    },
    /// Get a document by key.
    #[command(name = "data-get")]
    DataGet { collection: String, key: String },
    /// Insert a document (`--data` accepts JSON, `@path`, or `@-`).
    #[command(name = "data-insert")]
    DataInsert {
        collection: String,
        #[arg(long, value_name = "JSON_OR_@FILE")]
        data: String,
    },
    /// Update a document.
    #[command(name = "data-update")]
    DataUpdate {
        collection: String,
        key: String,
        #[arg(long, value_name = "JSON_OR_@FILE")]
        data: String,
    },
    /// Delete a document, or all documents if `key` is omitted.
    #[command(name = "data-rm")]
    DataRm {
        collection: String,
        key: Option<String>,
    },
    /// batch_save (upsert with a JSON array body).
    #[command(name = "data-batch-save")]
    DataBatchSave {
        collection: String,
        #[arg(long, value_name = "JSON_OR_@FILE")]
        data: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum KnowledgeCmd {
    /// List lookup-table-files.
    #[command(name = "lookup-ls")]
    LookupLs,
    /// Get a lookup-table-file entry.
    #[command(name = "lookup-get")]
    LookupGet { name: String },
    /// Delete a lookup-table-file entry.
    #[command(name = "lookup-rm")]
    LookupRm { name: String },

    /// List calcfields (props).
    #[command(name = "calcfields-ls")]
    CalcfieldsLs,
    /// List extractions (props).
    #[command(name = "extractions-ls")]
    ExtractionsLs,
    /// List field aliases (props).
    #[command(name = "fieldaliases-ls")]
    FieldaliasesLs,

    /// List transforms/lookups.
    #[command(name = "transforms-lookups-ls")]
    TransformsLookupsLs,
    /// List transforms/extractions.
    #[command(name = "transforms-extractions-ls")]
    TransformsExtractionsLs,

    /// List macros.
    #[command(name = "macros-ls")]
    MacrosLs,
    /// Get a macro.
    #[command(name = "macros-get")]
    MacrosGet { name: String },

    /// List tags.
    #[command(name = "tags-ls")]
    TagsLs,

    /// List event types.
    #[command(name = "eventtypes-ls")]
    EventtypesLs,
    /// Get an event type.
    #[command(name = "eventtypes-get")]
    EventtypesGet { name: String },

    /// List data models.
    #[command(name = "datamodel-ls")]
    DatamodelLs,
    /// Get a data model.
    #[command(name = "datamodel-get")]
    DatamodelGet { name: String },
}

#[derive(Subcommand, Debug)]
pub enum FederatedCmd {
    /// List federated providers.
    #[command(name = "provider-ls")]
    ProviderLs,
    /// Get a federated provider.
    #[command(name = "provider-get")]
    ProviderGet { name: String },
    /// Create a federated provider.
    #[command(name = "provider-create")]
    ProviderCreate {
        name: String,
        #[arg(long)]
        param: Vec<String>,
    },
    /// Delete a federated provider.
    #[command(name = "provider-rm")]
    ProviderRm { name: String },

    /// List federated indexes.
    #[command(name = "index-ls")]
    IndexLs,
    /// Get a federated index.
    #[command(name = "index-get")]
    IndexGet { name: String },
    /// Create a federated index.
    #[command(name = "index-create")]
    IndexCreate {
        name: String,
        #[arg(long)]
        param: Vec<String>,
    },
    /// Delete a federated index.
    #[command(name = "index-rm")]
    IndexRm { name: String },

    /// General federated search settings.
    Settings,
}

/// `index` (read-only) サブコマンド。
///
/// 書き込み系 (create / edit / remove) は README の方針どおり
/// ACS CLI (`admin.splunk.com`) の担当であり、ここには実装しない。
#[derive(Subcommand, Debug)]
pub enum IndexCmd {
    /// List data indexes (`/services/data/indexes`).
    #[command(name = "ls")]
    Ls {
        /// Maximum entries to return. 0 means "all" per Splunkd REST conventions.
        #[arg(long, default_value_t = 0)]
        count: i64,
        /// Return only summary fields (currentDBSizeMB / totalEventCount / minTime / maxTime).
        /// Maps to the Splunkd `summarize=true` query parameter.
        #[arg(long)]
        summarize: bool,
    },
    /// Get a data index by name.
    Get { name: String },
}

#[derive(Subcommand, Debug)]
pub enum MetricsCmd {
    /// List metric names.
    #[command(name = "names")]
    Names {
        #[arg(long, default_value = "-1h")]
        earliest: String,
        #[arg(long, default_value = "now")]
        latest: String,
        #[arg(long)]
        filter: Option<String>,
    },
    /// List dimensions for a metric.
    #[command(name = "dimensions")]
    Dimensions {
        #[arg(long, default_value = "*")]
        metric_name: String,
        #[arg(long, default_value = "-1h")]
        earliest: String,
        #[arg(long, default_value = "now")]
        latest: String,
        #[arg(long)]
        filter: Option<String>,
    },
    /// List rollup policies.
    #[command(name = "rollup-ls")]
    RollupLs,
}

#[derive(Subcommand, Debug)]
pub enum AlertCmd {
    /// List alert actions.
    #[command(name = "actions-ls")]
    ActionsLs,
    /// List fired alerts.
    #[command(name = "fired-ls")]
    FiredLs,
    /// Delete a fired alert entry.
    #[command(name = "fired-rm")]
    FiredRm { name: String },
}

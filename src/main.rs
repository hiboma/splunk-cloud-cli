use clap::{CommandFactory, Parser};
use splunk_cloud_cli::cli::{Cli, Command, OutputFormat};
use splunk_cloud_cli::client::SplunkClient;
use splunk_cloud_cli::commands;
use splunk_cloud_cli::config::{load_settings, resolve_credentials};
use splunk_cloud_cli::error::{Result, SplunkError};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    reset_sigpipe();
    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

// Rust's runtime installs SIGPIPE as SIG_IGN, which turns writes to a
// closed pipe into `ErrorKind::BrokenPipe` errors, which `println!`
// reports as a panic. Restore the default disposition so `head`, `less`,
// and similar tools terminate this process quietly — the customary
// behavior for Unix filters.
//
// If a future change needs to handle SIGPIPE explicitly (e.g. enabling
// tokio's `signal` feature and subscribing to `SignalKind::pipe`),
// revisit this: tokio's signal driver installs its own handler and
// would conflict with `SIG_DFL` here.
#[cfg(unix)]
fn reset_sigpipe() {
    // SAFETY: libc::signal is an FFI call; SIG_DFL restores the kernel
    // default handler, which is defined and side-effect free.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[cfg(not(unix))]
fn reset_sigpipe() {}

async fn run(cli: Cli) -> Result<()> {
    // `completion` does not touch credentials or config.
    if let Command::Completion { shell } = &cli.command {
        clap_complete::generate(
            *shell,
            &mut Cli::command(),
            "splunk-cloud-cli",
            &mut std::io::stdout(),
        );
        return Ok(());
    }

    let settings = load_settings()?;
    let format = cli
        .format
        .or(settings.format)
        .unwrap_or(OutputFormat::Pretty);

    let creds = resolve_credentials(cli.app.as_deref(), cli.user.as_deref(), &settings)?;
    let client = SplunkClient::new_with_debug(creds, cli.debug)?;

    match &cli.command {
        Command::Auth(c) => commands::auth::run(c, &client, format).await,
        Command::Search(c) => commands::search::run(c, &client, format).await,
        Command::SavedSearch(c) => commands::saved_search::run(c, &client, format).await,
        Command::Dashboard(c) => commands::dashboard::run(c, &client, format).await,
        Command::Kvstore(c) => commands::kvstore::run(c, &client, format).await,
        Command::Knowledge(c) => commands::knowledge::run(c, &client, format).await,
        Command::Federated(c) => commands::federated::run(c, &client, format).await,
        Command::Metrics(c) => commands::metrics::run(c, &client, format).await,
        Command::Alert(c) => commands::alert::run(c, &client, format).await,
        Command::Completion { .. } => Err(SplunkError::Config(
            "unreachable: handled above".to_string(),
        )),
    }
}

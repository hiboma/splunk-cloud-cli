use clap::{CommandFactory, Parser};
use splunk_cloud_cli::cli::{AuthCmd, Cli, Command, OutputFormat};
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
    // `completion` / `credentials` は Splunk への接続を必要としない（認証情報の
    // 解決自体が目的のサブコマンドもあるため、ここで先に処理する）。
    match &cli.command {
        Command::Completion { shell } => {
            clap_complete::generate(
                *shell,
                &mut Cli::command(),
                "splunk-cloud-cli",
                &mut std::io::stdout(),
            );
            return Ok(());
        }
        Command::Credentials(c) => {
            return commands::credentials::run(c);
        }
        Command::Doctor { no_connect, strict } => {
            // doctor は接続情報の解決を自前で診断するため、共通の
            // resolve_credentials / client 構築を経由しない。`--strict` で
            // 問題が見つかった場合は非ゼロ終了させる。
            let healthy = commands::doctor::run(*no_connect, *strict).await?;
            if !healthy {
                std::process::exit(1);
            }
            return Ok(());
        }
        _ => {}
    }

    let settings = load_settings()?;

    // `auth login` / `logout` / `status` は Splunk への接続を必要としない
    // （認証情報の取得・破棄・確認そのものが目的）。client を組む前に処理する。
    // `auth whoami` は接続が必要なので下のディスパッチに任せる。
    if let Command::Auth(c @ (AuthCmd::Login | AuthCmd::Logout | AuthCmd::Status)) = &cli.command {
        return commands::auth::run_oauth(c, &settings).await;
    }

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
        Command::Index(c) => commands::index::run(c, &client, format).await,
        Command::Metrics(c) => commands::metrics::run(c, &client, format).await,
        Command::Alert(c) => commands::alert::run(c, &client, format).await,
        Command::Completion { .. } | Command::Credentials(_) | Command::Doctor { .. } => Err(
            SplunkError::Config("unreachable: handled above".to_string()),
        ),
    }
}

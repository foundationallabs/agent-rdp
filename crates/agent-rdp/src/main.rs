//! agent-rdp: CLI tool for AI agents to control Windows Remote Desktop sessions.

mod cli;
mod error;
mod ipc_client;
mod output;
mod session_manager;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use cli::{Cli, Commands};
use output::Output;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let output = Output::new(cli.json);

    // A bad AGENT_RDP_STATE_DIR must fail before anything touches the state directory
    if let Err(e) = agent_rdp_daemon::check_state_dir() {
        output.print_error(e.error_code(), &e.to_string());
        std::process::exit(2);
    }

    // Logs go to stderr so stdout carries only command output (one JSON document with --json)
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    if let Err(e) = run(cli, &output).await {
        output.print_error(error::error_code(&e), &format!("{e:#}"));
        std::process::exit(1);
    }
}

async fn run(cli: Cli, output: &Output) -> anyhow::Result<()> {
    match cli.command {
        Commands::Connect(args) => {
            cli::commands::connect::run(&cli.session, args, output, cli.timeout, cli.stream_port)
                .await
        }
        Commands::Disconnect => {
            cli::commands::disconnect::run(&cli.session, output, cli.timeout).await
        }
        Commands::Screenshot(args) => {
            cli::commands::screenshot::run(&cli.session, args, output, cli.timeout).await
        }
        Commands::Mouse(args) => {
            cli::commands::mouse::run(&cli.session, args, output, cli.timeout).await
        }
        Commands::Keyboard(args) => {
            cli::commands::keyboard::run(&cli.session, args, output, cli.timeout).await
        }
        Commands::Scroll(args) => {
            cli::commands::scroll::run(&cli.session, args, output, cli.timeout).await
        }
        Commands::Clipboard(args) => {
            cli::commands::clipboard::run(&cli.session, args, output, cli.timeout).await
        }
        Commands::Drive(args) => {
            cli::commands::drive::run(&cli.session, args, output, cli.timeout).await
        }
        Commands::Automate(args) => {
            cli::commands::automate::run(&cli.session, args, output, cli.timeout).await
        }
        Commands::Locate(args) => {
            cli::commands::locate::run(&cli.session, args, output, cli.timeout).await
        }
        Commands::Session(args) => {
            cli::commands::session::run(&cli.session, args, output, cli.timeout).await
        }
        Commands::Wait { ms } => cli::commands::wait::run(ms).await,
        Commands::View(args) => cli::commands::view::run(args, output).await,
    }
}

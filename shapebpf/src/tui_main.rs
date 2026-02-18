mod daemon;
mod tui;

use anyhow::Result;
use clap::Parser;

use tui::app::App;
use tui::ipc_client::IpcClient;

const DEFAULT_SOCKET: &str = "/run/shapebpf/shapebpf.sock";

#[derive(Parser)]
#[command(name = "shapebpf-tui", about = "shapeBPF TUI client")]
struct Cli {
    /// Path to daemon socket
    #[arg(short, long, default_value = DEFAULT_SOCKET)]
    socket: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let client = IpcClient::connect(&cli.socket).await?;
    let app = App::new(client).await;

    let terminal = ratatui::init();
    let result = app.run(terminal).await;
    ratatui::restore();
    result
}

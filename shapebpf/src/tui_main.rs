mod daemon;
mod tui;

use anyhow::Result;
use clap::Parser;
use shapebpf_common::ipc::{Request, Response};

use tui::app::App;
use tui::ipc_client::IpcClient;

const DEFAULT_SOCKET: &str = "/run/shapebpf/shapebpf.sock";

#[derive(Parser)]
#[command(name = "shapebpf-tui", about = "shapeBPF TUI client")]
struct Cli {
    /// Path to daemon socket
    #[arg(short, long, default_value = DEFAULT_SOCKET)]
    socket: String,

    /// Dump stats JSON and exit (debug)
    #[arg(long)]
    dump_stats: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.dump_stats {
        let mut client = IpcClient::connect(&cli.socket).await?;
        if let Ok(Response::Stats(stats)) = client.request(&Request::GetStats).await {
            for s in &stats {
                let procs: Vec<&str> = s.processes.iter().map(|p| p.comm.as_str()).collect();
                println!(
                    "cgroup={} procs={:?} tx={} rx={}",
                    s.cgroup_path,
                    procs,
                    s.stats.tx_bytes,
                    s.stats.rx_bytes,
                );
            }
        }
        return Ok(());
    }

    let client = IpcClient::connect(&cli.socket).await?;
    let app = App::new(client).await;

    let terminal = ratatui::init();
    let result = app.run(terminal).await;
    ratatui::restore();
    result
}

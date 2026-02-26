//! Entry point for `tcp-over-udp`.
//!
//! Parses CLI arguments and dispatches into either **server** or **client** mode.
//! All actual protocol work is delegated to library modules; `main.rs` owns only
//! process setup (logging, signal handling, argument parsing).

use clap::{Parser, Subcommand};

/// TCP-like reliable byte stream over UDP.
#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    /// Run as a server, listening for incoming connections.
    Server {
        /// Local address to bind (e.g. 0.0.0.0:9000).
        #[arg(short, long, default_value = "0.0.0.0:9000")]
        bind: String,
    },
    /// Run as a client, connecting to a remote server.
    Client {
        /// Remote server address (e.g. 127.0.0.1:9000).
        #[arg(short, long)]
        server: String,
    },
}

#[tokio::main]
async fn main() {
    // Initialise env_logger; set RUST_LOG to control verbosity.
    env_logger::init();

    let cli = Cli::parse();

    match cli.mode {
        Mode::Server { bind } => {
            log::info!("Starting server on {bind}");
            // TODO: call tcp_over_udp::server::run(&bind).await
        }
        Mode::Client { server } => {
            log::info!("Starting client, connecting to {server}");
            // TODO: call tcp_over_udp::client::run(&server).await
        }
    }
}

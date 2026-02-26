//! Entry point for `tcp-over-udp`.
//!
//! # Usage
//!
//! Run the server in one terminal:
//! ```
//! RUST_LOG=debug cargo run -- server --bind 127.0.0.1:9000
//! ```
//!
//! Then run the client in another:
//! ```
//! RUST_LOG=debug cargo run -- client --server 127.0.0.1:9000
//! ```
//!
//! The client sends "Ping!" and the server echoes "Pong!".

use std::net::SocketAddr;

use clap::{Parser, Subcommand};
use tcp_over_udp::{
    connection::{ConnError, Connection},
    socket::Socket,
};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// TCP-like reliable byte stream over UDP.
#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    /// Listen for one incoming connection, receive a message, echo a reply.
    Server {
        /// Local address to bind (e.g. 127.0.0.1:9000).
        #[arg(short, long, default_value = "0.0.0.0:9000")]
        bind: String,
    },
    /// Connect to the server, send "Ping!", receive "Pong!".
    Client {
        /// Remote server address (e.g. 127.0.0.1:9000).
        #[arg(short, long)]
        server: String,
    },
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    env_logger::init();

    let cli = Cli::parse();

    let result = match cli.mode {
        Mode::Server { bind } => run_server(bind).await,
        Mode::Client { server } => run_client(server).await,
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

async fn run_server(bind: String) -> Result<(), ConnError> {
    let addr: SocketAddr = bind.parse().expect("invalid bind address");
    let socket = Socket::bind(addr).await.map_err(ConnError::Socket)?;
    log::info!("server listening on {}", socket.local_addr);

    let mut conn = Connection::accept(socket).await?;
    log::info!("connection established");

    // Receive one message from the client.
    match conn.recv().await {
        Ok(data) => {
            log::info!("received: {:?}", String::from_utf8_lossy(&data));
            // Echo a reply.
            conn.send(b"Pong!").await?;
            log::info!("sent: \"Pong!\"");
        }
        Err(ConnError::Eof) => log::info!("client closed the connection"),
        Err(e) => return Err(e),
    }

    conn.close().await?;
    log::info!("server done");
    Ok(())
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

async fn run_client(server: String) -> Result<(), ConnError> {
    let peer: SocketAddr = server.parse().expect("invalid server address");
    // Bind to an OS-assigned ephemeral port.
    let local: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let socket = Socket::bind(local).await.map_err(ConnError::Socket)?;

    log::info!("connecting to {peer} from {}", socket.local_addr);
    let mut conn = Connection::connect(socket, peer).await?;
    log::info!("connection established");

    conn.send(b"Ping!").await?;
    log::info!("sent: \"Ping!\"");

    match conn.recv().await {
        Ok(data) => log::info!("received: {:?}", String::from_utf8_lossy(&data)),
        Err(ConnError::Eof) => log::info!("server closed the connection"),
        Err(e) => return Err(e),
    }

    conn.close().await?;
    log::info!("client done");
    Ok(())
}

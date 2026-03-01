//! Entry point for `tcp-over-udp`.
//!
//! # Stop-and-wait demo
//!
//! ```text
//! RUST_LOG=debug cargo run -- server --bind 127.0.0.1:9000
//! RUST_LOG=debug cargo run -- client --server 127.0.0.1:9000
//! ```
//!
//! # Go-Back-N demo (pipelined, window = 4)
//!
//! ```text
//! RUST_LOG=debug cargo run -- gbn-server --bind 127.0.0.1:9001
//! RUST_LOG=debug cargo run -- gbn-client --server 127.0.0.1:9001 --window 4
//! ```

use std::net::SocketAddr;

use clap::{Parser, Subcommand};
use tcp_over_udp::{
    connection::{ConnError, Connection},
    gbn_connection::GbnConnection,
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
    /// Stop-and-wait server: receive one message, echo a reply.
    Server {
        #[arg(short, long, default_value = "0.0.0.0:9000")]
        bind: String,
    },
    /// Stop-and-wait client: send "Ping!", receive "Pong!".
    Client {
        #[arg(short, long)]
        server: String,
    },
    /// Go-Back-N server: receive multiple pipelined messages, echo each one.
    GbnServer {
        #[arg(short, long, default_value = "0.0.0.0:9001")]
        bind: String,
        /// GBN receive window size N.
        #[arg(short, long, default_value_t = 4)]
        window: usize,
    },
    /// Go-Back-N client: pipeline N messages without waiting for individual ACKs.
    GbnClient {
        #[arg(short, long)]
        server: String,
        /// GBN send window size N.
        #[arg(short, long, default_value_t = 4)]
        window: usize,
        /// Number of messages to send in a pipeline burst.
        #[arg(short, long, default_value_t = 8)]
        count: usize,
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
        Mode::GbnServer { bind, window } => run_gbn_server(bind, window).await,
        Mode::GbnClient { server, window, count } => run_gbn_client(server, window, count).await,
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

// ---------------------------------------------------------------------------
// GBN server
// ---------------------------------------------------------------------------

async fn run_gbn_server(bind: String, window: usize) -> Result<(), ConnError> {
    let addr: SocketAddr = bind.parse().expect("invalid bind address");
    let socket = Socket::bind(addr).await.map_err(ConnError::Socket)?;
    log::info!("gbn-server listening on {} (window={})", socket.local_addr, window);

    let mut conn = GbnConnection::accept(socket, window).await?;
    log::info!("gbn connection established");

    // Receive messages until the client closes, echoing each one back.
    loop {
        match conn.recv().await {
            Ok(data) => {
                let msg = String::from_utf8_lossy(&data);
                log::info!("gbn-server received: {:?}", msg);
                conn.send(&data).await?; // echo
            }
            Err(ConnError::Eof) => {
                log::info!("gbn-server: client closed connection");
                break;
            }
            Err(e) => return Err(e),
        }
    }

    conn.close().await?;
    log::info!("gbn-server done");
    Ok(())
}

// ---------------------------------------------------------------------------
// GBN client
// ---------------------------------------------------------------------------

async fn run_gbn_client(server: String, window: usize, count: usize) -> Result<(), ConnError> {
    let peer: SocketAddr = server.parse().expect("invalid server address");
    let local: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let socket = Socket::bind(local).await.map_err(ConnError::Socket)?;

    log::info!("gbn-client connecting to {peer} (window={window}, count={count})");
    let mut conn = GbnConnection::connect(socket, peer, window).await?;
    log::info!("gbn connection established");

    // Pipeline `count` messages: send all, flush, then collect echoes.
    for i in 0..count {
        let msg = format!("msg-{i:03}");
        conn.send(msg.as_bytes()).await?;
        log::info!("gbn-client → {:?}", msg);
    }

    // Wait for all sends to be acknowledged.
    conn.flush().await?;
    log::info!("gbn-client: all {} messages sent and acknowledged", count);

    // Collect the server's echoes.
    for _ in 0..count {
        match conn.recv().await {
            Ok(data) => log::info!("gbn-client ← {:?}", String::from_utf8_lossy(&data)),
            Err(ConnError::Eof) => break,
            Err(e) => return Err(e),
        }
    }

    conn.close().await?;
    log::info!("gbn-client done");
    Ok(())
}

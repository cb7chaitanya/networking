use anyhow::Result;
use dns_resolver::server;
use std::env;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let mut dns_port: u16 = 1053;
    let mut http_port: u16 = 8080;

    for (i, arg) in args.iter().enumerate() {
        match arg.as_str() {
            "--dns-port" => {
                if let Some(port_str) = args.get(i + 1) {
                    dns_port = port_str.parse().unwrap_or(1053);
                }
            }
            "--http-port" => {
                if let Some(port_str) = args.get(i + 1) {
                    http_port = port_str.parse().unwrap_or(8080);
                }
            }
            _ => {}
        }
    }

    server::run_server(dns_port, http_port).await;

    Ok(())
}

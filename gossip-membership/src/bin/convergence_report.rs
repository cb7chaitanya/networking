use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::Parser;
use gossip_membership::gossip;
use gossip_membership::membership::MembershipTable;
use gossip_membership::message::MessagePayload;
use gossip_membership::node::{NodeConfig, NodeState};
use gossip_membership::runner::{run_node, Node};
use gossip_membership::transport::Transport;
use plotters::prelude::*;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;

#[derive(Parser, Debug)]
#[command(author, version, about = "Measure gossip convergence and write graphs")]
struct Args {
    #[arg(long, default_value_t = 1)]
    trials: usize,
    #[arg(long, default_value_t = 5_000)]
    timeout_ms: u64,
    #[arg(long, default_value_t = 20)]
    poll_ms: u64,
    #[arg(long, default_value = "target/convergence-report")]
    out_dir: PathBuf,
}

#[derive(Debug, Clone)]
struct Experiment {
    scenario: &'static str,
    x_value: usize,
    cluster_size: usize,
    max_gossip_sends: usize,
    gossip_fanout: usize,
}

#[derive(Debug, Clone)]
struct Measurement {
    scenario: &'static str,
    trial: usize,
    x_value: usize,
    cluster_size: usize,
    max_gossip_sends: usize,
    gossip_fanout: usize,
    encoded_message_bytes: usize,
    convergence_ms: u128,
}

#[derive(Debug, Deserialize)]
struct MembershipResponse {
    nodes: Vec<MembershipNode>,
}

#[derive(Debug, Deserialize)]
struct MembershipNode {
    id: String,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    fs::create_dir_all(&args.out_dir)?;

    let experiments = build_experiments();
    let mut measurements = Vec::new();

    for trial in 0..args.trials {
        for exp in &experiments {
            eprintln!(
                "running scenario={} trial={} cluster={} fanout={} message_fanout={}",
                exp.scenario,
                trial + 1,
                exp.cluster_size,
                exp.max_gossip_sends,
                exp.gossip_fanout,
            );
            let convergence_ms = run_experiment(
                exp,
                Duration::from_millis(args.timeout_ms),
                Duration::from_millis(args.poll_ms),
            )
            .await?;
            let encoded_message_bytes =
                estimate_gossip_message_size(exp.cluster_size, exp.gossip_fanout)?;
            measurements.push(Measurement {
                scenario: exp.scenario,
                trial: trial + 1,
                x_value: exp.x_value,
                cluster_size: exp.cluster_size,
                max_gossip_sends: exp.max_gossip_sends,
                gossip_fanout: exp.gossip_fanout,
                encoded_message_bytes,
                convergence_ms: convergence_ms.as_millis(),
            });
        }
    }

    write_csv(&args.out_dir.join("convergence.csv"), &measurements)?;
    draw_chart(
        &args.out_dir.join("cluster_size_vs_convergence.png"),
        "Cluster Size vs Convergence",
        "Cluster Size",
        average_points(&measurements, "cluster_size", |m| m.cluster_size as f64),
    )?;
    draw_chart(
        &args.out_dir.join("fanout_vs_convergence.png"),
        "Fanout vs Convergence",
        "Gossip Targets per Round",
        average_points(&measurements, "fanout", |m| m.max_gossip_sends as f64),
    )?;
    draw_chart(
        &args.out_dir.join("message_size_vs_convergence.png"),
        "Message Size vs Convergence",
        "Encoded Gossip Message Size (bytes)",
        average_points(&measurements, "message_size", |m| {
            m.encoded_message_bytes as f64
        }),
    )?;

    eprintln!(
        "wrote {} measurements to {}",
        measurements.len(),
        args.out_dir.display()
    );
    Ok(())
}

fn build_experiments() -> Vec<Experiment> {
    let mut experiments = Vec::new();

    for cluster_size in [4usize, 8, 12, 16] {
        experiments.push(Experiment {
            scenario: "cluster_size",
            x_value: cluster_size,
            cluster_size,
            max_gossip_sends: 2,
            gossip_fanout: 6,
        });
    }

    for max_gossip_sends in [1usize, 2, 3, 4] {
        experiments.push(Experiment {
            scenario: "fanout",
            x_value: max_gossip_sends,
            cluster_size: 12,
            max_gossip_sends,
            gossip_fanout: 6,
        });
    }

    for gossip_fanout in [2usize, 4, 6, 8, 10, 12] {
        experiments.push(Experiment {
            scenario: "message_size",
            x_value: gossip_fanout,
            cluster_size: 12,
            max_gossip_sends: 2,
            gossip_fanout,
        });
    }

    experiments
}

fn benchmark_config(
    max_gossip_sends: usize,
    gossip_fanout: usize,
    metrics_port: u16,
) -> NodeConfig {
    let mut cfg = NodeConfig::fast();
    cfg.heartbeat_interval_ms = 40;
    cfg.gossip_interval_ms = 40;
    cfg.probe_interval_ms = 10_000;
    cfg.probe_timeout_ms = 10_000;
    cfg.suspect_timeout_ms = 20_000;
    cfg.suspect_timeout_multiplier = 0.0;
    cfg.suspect_timeout_jitter_ms = 0;
    cfg.max_gossip_sends = max_gossip_sends;
    cfg.adaptive_gossip_targets = false;
    cfg.gossip_fanout = gossip_fanout;
    cfg.adaptive_fanout = false;
    cfg.piggyback_max = gossip_fanout;
    cfg.anti_entropy_interval_ms = 0;
    cfg.metrics_log_interval_ms = 20;
    cfg.metrics_server_port = metrics_port;
    cfg.inbound_global_capacity = 0;
    cfg.inbound_global_refill_rate = 0;
    cfg.inbound_peer_capacity = 0;
    cfg.inbound_peer_refill_rate = 0;
    cfg
}

async fn run_experiment(
    exp: &Experiment,
    timeout: Duration,
    poll_interval: Duration,
) -> Result<Duration, Box<dyn std::error::Error>> {
    let mut transports = Vec::with_capacity(exp.cluster_size);
    let mut addrs = Vec::with_capacity(exp.cluster_size);
    for _ in 0..exp.cluster_size {
        let transport = bind_local().await?;
        addrs.push(transport.local_addr);
        transports.push(transport);
    }

    let metrics_ports: Vec<u16> = (0..exp.cluster_size)
        .map(|_| reserve_port())
        .collect::<io::Result<_>>()?;
    let hub_addr = addrs[0];

    let nodes: Vec<Node> = transports
        .into_iter()
        .enumerate()
        .map(|(index, transport)| {
            let peers: Vec<SocketAddr> = if index == 0 {
                addrs[1..].to_vec()
            } else {
                vec![hub_addr]
            };
            let cfg = benchmark_config(
                exp.max_gossip_sends,
                exp.gossip_fanout,
                metrics_ports[index],
            );
            Node::new(transport, cfg, &peers)
        })
        .collect();

    let expected_ids: Vec<u64> = nodes.iter().map(|node| node.id).collect();

    let mut handles = Vec::with_capacity(exp.cluster_size);
    let mut shutdowns = Vec::with_capacity(exp.cluster_size);
    for node in nodes {
        let (tx, rx) = oneshot::channel();
        shutdowns.push(tx);
        handles.push(tokio::spawn(run_node(node, rx)));
    }

    let start = Instant::now();
    let convergence = loop {
        if start.elapsed() > timeout {
            break Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "scenario={} cluster={} fanout={} message_fanout={} timed out after {} ms",
                    exp.scenario,
                    exp.cluster_size,
                    exp.max_gossip_sends,
                    exp.gossip_fanout,
                    timeout.as_millis(),
                ),
            ));
        }

        if cluster_converged(&metrics_ports, &expected_ids).await {
            break Ok(start.elapsed());
        }

        tokio::time::sleep(poll_interval).await;
    };

    for tx in shutdowns {
        let _ = tx.send(());
    }
    for handle in handles {
        let _ = handle.await;
    }

    convergence.map_err(|err| Box::new(err) as Box<dyn std::error::Error>)
}

async fn cluster_converged(metrics_ports: &[u16], expected_ids: &[u64]) -> bool {
    for &port in metrics_ports {
        let members = match fetch_membership_ids(port).await {
            Ok(members) => members,
            Err(_) => return false,
        };
        if !expected_ids.iter().all(|id| members.contains(id)) {
            return false;
        }
    }
    true
}

async fn fetch_membership_ids(port: u16) -> Result<Vec<u64>, Box<dyn std::error::Error>> {
    let mut stream = match tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await {
        Ok(stream) => stream,
        Err(err) => return Err(Box::new(err)),
    };
    stream
        .write_all(b"GET /membership HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;

    let response = String::from_utf8(response)?;
    let body = response
        .split("\r\n\r\n")
        .nth(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP body"))?;
    let parsed: MembershipResponse = serde_json::from_str(body)?;
    let ids = parsed
        .nodes
        .into_iter()
        .filter_map(|node| node.id.parse::<u64>().ok())
        .collect();
    Ok(ids)
}

fn estimate_gossip_message_size(
    cluster_size: usize,
    gossip_fanout: usize,
) -> Result<usize, Box<dyn std::error::Error>> {
    let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_000);
    let mut table = MembershipTable::new(1, local_addr);
    for index in 0..cluster_size.saturating_sub(1) {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_001 + index as u16);
        let mut state = NodeState::new_alive(10 + index as u64, addr, 1);
        state.last_update = Instant::now();
        table.merge_entry(&state);
    }

    let msg = gossip::build_gossip_message(&table, 1, 0, 0, gossip_fanout);
    match &msg.payload {
        MessagePayload::Gossip(entries) => {
            if entries.is_empty() {
                return Err(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expected a non-empty gossip payload",
                )));
            }
        }
        _ => unreachable!(),
    }
    Ok(msg.encode()?.len())
}

async fn bind_local() -> Result<Transport, Box<dyn std::error::Error>> {
    Ok(Transport::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?)
}

fn reserve_port() -> io::Result<u16> {
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    Ok(listener.local_addr()?.port())
}

fn write_csv(path: &Path, measurements: &[Measurement]) -> io::Result<()> {
    let mut csv = String::from(
        "scenario,trial,x_value,cluster_size,fanout,message_fanout,encoded_message_bytes,convergence_ms\n",
    );
    for m in measurements {
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            m.scenario,
            m.trial,
            m.x_value,
            m.cluster_size,
            m.max_gossip_sends,
            m.gossip_fanout,
            m.encoded_message_bytes,
            m.convergence_ms,
        ));
    }
    fs::write(path, csv)
}

fn average_points<F>(measurements: &[Measurement], scenario: &str, x_fn: F) -> Vec<(f64, f64)>
where
    F: Fn(&Measurement) -> f64,
{
    let mut buckets: BTreeMap<i64, Vec<u128>> = BTreeMap::new();
    for measurement in measurements.iter().filter(|m| m.scenario == scenario) {
        let x = (x_fn(measurement) * 1000.0).round() as i64;
        buckets
            .entry(x)
            .or_default()
            .push(measurement.convergence_ms);
    }

    buckets
        .into_iter()
        .map(|(x, values)| {
            let avg = values.iter().copied().sum::<u128>() as f64 / values.len() as f64;
            (x as f64 / 1000.0, avg)
        })
        .collect()
}

fn draw_chart(
    path: &Path,
    title: &str,
    x_label: &str,
    points: Vec<(f64, f64)>,
) -> Result<(), Box<dyn std::error::Error>> {
    if points.is_empty() {
        return Ok(());
    }

    let x_min = points.first().map(|point| point.0).unwrap_or(0.0);
    let x_max = points.last().map(|point| point.0).unwrap_or(1.0);
    let y_max = points
        .iter()
        .map(|point| point.1)
        .fold(0.0_f64, f64::max)
        .max(1.0);

    let root = BitMapBackend::new(path, (960, 540)).into_drawing_area();
    root.fill(&WHITE)?;

    let mut chart = ChartBuilder::on(&root)
        .caption(title, ("sans-serif", 28))
        .margin(24)
        .x_label_area_size(48)
        .y_label_area_size(56)
        .build_cartesian_2d(x_min..x_max, 0.0..(y_max * 1.15))?;

    chart
        .configure_mesh()
        .x_desc(x_label)
        .y_desc("Convergence Time (ms)")
        .axis_desc_style(("sans-serif", 18))
        .label_style(("sans-serif", 14))
        .draw()?;

    chart.draw_series(LineSeries::new(points.iter().copied(), &BLUE))?;
    chart.draw_series(
        points
            .iter()
            .map(|(x, y)| Circle::new((*x, *y), 5, BLUE.filled())),
    )?;
    root.present()?;
    Ok(())
}

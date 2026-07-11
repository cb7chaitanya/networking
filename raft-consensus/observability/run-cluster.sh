#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Building release binary..."
cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml"

BINARY="$REPO_ROOT/target/release/raft_node"

# Kill any previously running cluster nodes
pkill -f "raft_node --id" 2>/dev/null || true
sleep 0.3

echo "Starting 3-node cluster..."

"$BINARY" \
  --id 1 \
  --addr 127.0.0.1:7001 \
  --peer 2=127.0.0.1:7002 \
  --peer 3=127.0.0.1:7003 \
  --metrics 127.0.0.1:9001 \
  --tick-ms 10 &

"$BINARY" \
  --id 2 \
  --addr 127.0.0.1:7002 \
  --peer 1=127.0.0.1:7001 \
  --peer 3=127.0.0.1:7003 \
  --metrics 127.0.0.1:9002 \
  --tick-ms 10 &

"$BINARY" \
  --id 3 \
  --addr 127.0.0.1:7003 \
  --peer 1=127.0.0.1:7001 \
  --peer 2=127.0.0.1:7002 \
  --metrics 127.0.0.1:9003 \
  --tick-ms 10 &

echo ""
echo "Cluster started. Metrics endpoints:"
echo "  Node 1: http://127.0.0.1:9001/metrics"
echo "  Node 2: http://127.0.0.1:9002/metrics"
echo "  Node 3: http://127.0.0.1:9003/metrics"
echo ""
echo "Prometheus: http://localhost:9090"
echo "Grafana:    http://localhost:3000  (admin / admin)"
echo ""
echo "To start the observability stack:"
echo "  cd observability && docker compose up -d"
echo ""
echo "Press Ctrl-C to stop all cluster nodes."
wait

#!/usr/bin/env bash
# Launch a 3-node gossip cluster with Prometheus metrics endpoints.
#
# Gossip ports:  7000, 7001, 7002
# Metrics ports: 9100, 9101, 9102
#
# Usage:
#   ./observability/run-cluster.sh          # plaintext
#   ./observability/run-cluster.sh --key    # encrypted (generates a shared key)
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --release 2>&1 | tail -1
BIN=target/release/gossip-membership

KEY_FLAG=""
if [[ "${1:-}" == "--key" ]]; then
    KEY=$($BIN --generate-key)
    KEY_FLAG="--cluster-key $KEY"
    echo "cluster key: $KEY"
fi

echo "starting 3-node cluster..."
echo "  node0: gossip=127.0.0.1:7000  metrics=http://localhost:9100/metrics"
echo "  node1: gossip=127.0.0.1:7001  metrics=http://localhost:9101/metrics"
echo "  node2: gossip=127.0.0.1:7002  metrics=http://localhost:9102/metrics"
echo ""
echo "press Ctrl-C to stop all nodes"
echo ""

trap 'kill $(jobs -p) 2>/dev/null; wait' EXIT

$BIN --bind 127.0.0.1:7000 --metrics-port 9100 $KEY_FLAG &
sleep 0.2
$BIN --bind 127.0.0.1:7001 --peers 127.0.0.1:7000 --metrics-port 9101 $KEY_FLAG &
sleep 0.2
$BIN --bind 127.0.0.1:7002 --peers 127.0.0.1:7000,127.0.0.1:7001 --metrics-port 9102 $KEY_FLAG &

wait

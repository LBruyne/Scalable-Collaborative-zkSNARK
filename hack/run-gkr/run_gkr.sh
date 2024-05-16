# Check if IP address is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <server id> <log m> <log l>"
    exit 1
fi

# Check if IP address is provided
if [ -z "$2" ]; then
    echo "Usage: $0 <server id> <log m> <log l>"
    exit 1
fi

# Check if IP address is provided
if [ -z "$3" ]; then
    echo "Usage: $0 <server id> <log m> <log l>"
    exit 1
fi

server_id="$1"
m=$2
l=$((2**$3))

cd /tmp/distributed-GKR
sleep 1
RUST_LOG=debug ./target/release/examples/gkr --l $l --depth 16 --width $m | tee /tmp/zksaas.log
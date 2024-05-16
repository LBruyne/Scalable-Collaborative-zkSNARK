l=32
t=1
n=128

# Check if IP address is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <server id> <m>"
    exit 1
fi

# Check if IP address is provided
if [ -z "$2" ]; then
    echo "Usage: $0 <server id> <m>"
    exit 1
fi

server_id="$1"
m=$((2**$2))

cd /tmp/zksaas
ps aux | awk '/plonk_bench/ && !/awk/ {print $2}' | xargs kill
sleep 1
RUST_LOG=debug ./target/release/examples/plonk_bench $server_id ./network-address/$n $l $t $m | tee /tmp/zksaas.log
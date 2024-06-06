
if [ -z "$1" ]; then
    echo "Usage: $0 <ip_address_file> <ip>"
    exit 1
fi

if [ -z "$2" ]; then
    echo "Usage: $0 <ip_address_file> <ip>"
    exit 1
fi


address_file="$1"
ip="$2"

scp -i ~/.ssh/zkp.pem ~/.ssh/zkp.pem root@$2:/root/.ssh/
ssh -i ~/.ssh/zkp.pem root@$2 "/bin/bash -s" <<EOF 
            # Change to the directory where the zip file is located
            cd /root
            mkdir hyperplonk
            mkdir zksaas
            mkdir gkr
            mkdir hyperplonk/output
            mkdir zksaas/output
            mkdir gkr/output
            exit
EOF

cp $address_file "$(dirname "$0")/ip_addresses.txt"
cd "$(dirname "$0")"
cp ip_addresses.txt run-hyperplonk/ip_addresses.txt
cp ip_addresses.txt run-gkr/ip_addresses.txt
cp ip_addresses.txt run-zksaas/ip_addresses.txt
mkdir network-address

while IFS= read -r ip_address; do
    echo "${ip_address}:10086"
done < "ip_addresses.txt" > "ip_addresses_port.txt"

for ((i=3;i<8;i++)); do
    head -n $((2**$i)) "ip_addresses_port.txt" > ./network-address/$((2**$i))
done

pushd run-hyperplonk
    bash pack.sh
    scp -i ~/.ssh/zkp.pem tmp.zip run.sh ip_addresses.txt handle_server.sh root@$2:/root/hyperplonk/
popd

pushd run-gkr
    bash pack.sh
    scp -i ~/.ssh/zkp.pem tmp.zip run.sh ip_addresses.txt handle_server.sh root@$2:/root/gkr/
popd

pushd run-zksaas
    bash pack.sh
    scp -i ~/.ssh/zkp.pem tmp.zip run.sh ip_addresses.txt handle_server.sh root@$2:/root/zksaas/
popd

rm ip_addresses.txt
rm ip_addresses_port.txt
rm -rf network-address


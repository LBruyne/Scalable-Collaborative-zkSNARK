pushd hyperplonk
    bash ./handle_server.sh ./ip_addresses.txt
popd

pushd hyperplonk-dataparallel
    bash ./handle_server.sh ./ip_addresses.txt
popd

# pushd zksaas
#     bash ./handle_server.sh ./ip_addresses.txt
# popd

pushd cpermcheck
    bash ./handle_server.sh ./ip_addresses.txt
popd

pushd dpermcheck
    bash ./handle_server.sh ./ip_addresses.txt
popd
rm tmp.zip
rm -rf tmp
pushd /home/asternight/code/zksaas
cargo +nightly build --release --example plonk_bench
popd
mkdir tmp
cp /home/asternight/code/zksaas/target/release/examples/plonk_bench ./tmp/plonk_bench
cp -r ../network-address ./tmp
zip -r ./tmp.zip ./tmp
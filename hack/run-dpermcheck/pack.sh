rm tmp.zip
rm -rf tmp
just build --release -F benchmark --example bench_dpermcheck
mkdir tmp
cp ../../target/release/examples/bench_dpermcheck ./tmp/bench_dpermcheck
cp -r ../network-address ./tmp
zip -r ./tmp.zip ./tmp
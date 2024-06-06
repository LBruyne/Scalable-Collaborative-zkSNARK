rm tmp.zip
rm -rf tmp
just build --release -F benchmark --example bench_gkr
mkdir tmp
cp ../../target/release/examples/bench_gkr ./tmp/bench_gkr
cp -r ../network-address ./tmp
zip -r ./tmp.zip ./tmp
rm tmp.zip
rm -rf tmp
just build --release -F benchmark --example bench_cpermcheck
mkdir tmp
cp ../../target/release/examples/bench_cpermcheck ./tmp/bench_cpermcheck
cp -r ../network-address ./tmp
zip -r ./tmp.zip ./tmp
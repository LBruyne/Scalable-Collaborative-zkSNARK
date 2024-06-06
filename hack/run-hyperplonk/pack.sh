rm tmp.zip
rm -rf tmp
just build --release -F benchmark --example bench_hyperplonk
mkdir tmp
cp ../../target/release/examples/bench_hyperplonk ./tmp/bench_hyperplonk
cp -r ../network-address ./tmp
zip -r ./tmp.zip ./tmp
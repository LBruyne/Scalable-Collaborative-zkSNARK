rm tmp.zip
rm -rf tmp
just build --release -F benchmark --example bench_hyperplonk_dataparallel
mkdir tmp
cp ../../target/release/examples/bench_hyperplonk_dataparallel ./tmp/bench_hyperplonk_dataparallel
cp -r ../network-address ./tmp
zip -r ./tmp.zip ./tmp
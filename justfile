RUSTFLAGS:= "\"-Ctarget-cpu=native --cfg tokio_unstable\""

CARGO:= "RUSTFLAGS="+RUSTFLAGS+" cargo +nightly"
build:
    {{CARGO}} build

run *params:
    {{CARGO}} run {{params}}

test:
    {{CARGO}} test

bench:
    {{CARGO}} bench

perf *params:
    {{CARGO}} flamegraph {{params}}
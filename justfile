RUSTFLAGS:= "-Ctarget-cpu=native"

CARGO:= "RUSTFLAGS="+RUSTFLAGS+" cargo +nightly"
build:
    {{CARGO}} build

run:
    {{CARGO}} run

run-params params:
    {{CARGO}} run {{params}}

test:
    {{CARGO}} test

bench:
    {{CARGO}} bench

perf params:
    {{CARGO}} flamegraph {{params}}
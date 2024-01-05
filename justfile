RUSTFLAGS:= "\"-Ctarget-cpu=native -Awarnings\""

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
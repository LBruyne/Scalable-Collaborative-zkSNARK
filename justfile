RUSTFLAGS:= "\"-Ctarget-cpu=native -Awarnings\""

CARGO:= "RUSTFLAGS="+RUSTFLAGS+" cargo +nightly"
build *params:
    {{CARGO}} build {{params}}

run *params:
    {{CARGO}} run {{params}}

test:
    {{CARGO}} test

bench:
    {{CARGO}} bench

perf *params:
    {{CARGO}} flamegraph {{params}}
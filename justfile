RUSTFLAGS:= "-Ctarget-cpu=native"

CARGO:= "RUSTFLAGS="+RUSTFLAGS+" cargo +nightly"
build:
    {{CARGO}} build

run:
    {{CARGO}} run

test:
    {{CARGO}} test

bench:
    {{CARGO}} bench
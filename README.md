# Collaborative-GKR

Rust implementation of the paper [Scalable Collaborative {zk-SNARK}: Fully Distributed Proof Generation and Malicious Security](https://eprint.iacr.org/2024/143).

To find the evaluations, check the examples in `dist-primitive`, `gkr` and the scripts in `hack`. 

The project is built upon [arkworks ecosystem](https://github.com/arkworks-rs).

## How to run

If you got [`just`](https://github.com/casey/just) at hand, simply run:

```bash
just run --release --example <example name>
```

Or run the examples with raw cargo commands:
```bash
RUSTFLAGS="-Ctarget-cpu=native -Awarnings" cargo +nightly run --release --example <example name>
```

For example, run the POC GKR implementation:
```bash
just run --release --example gkr -- --l 32 --depth 16 --width 21
```

For benchmarks of the distributed primitives, please check `hack/bench_poly_comm.sh` and `hack/bench_sumcheck.sh`.

## Project layout

- `dist-primitive`: The distributed primitives, including dMSM, dPolyCommit and dSumcheck.
- `gkr`: The GKR protocol. 
- `hack`: Scripts for running the experiments.
- `mpc-net`: The network layer for the MPC.
- `secret-sharing`: The packed secret sharing scheme.

## License

This library is released under the MIT License.

# Collaborative-GKR

Rust implementation of the paper "Scalable Collaborative zk-SNARK: Fully Distributed Proof Generation and Malicious Security".

To find the evaluations, check the examples in `dist-primitive`, `gkr` and the scripts in `hack`. 

The project is built upon [arkworks ecosystem](https://github.com/arkworks-rs).

## Illustration

This is a Proof-of-Concept implementation. In the paper, we assume a P2P network for the MPC protocol to run smoothly. In the actual implementation, we only implement a peer which can be run by an low-specific instance. We estimated the overall efficiency by calculating the computational, memory, and communication costs incurred by a node during a single proof generation process.

## How to run

If you got [`just`](https://github.com/casey/just) at hand, simply run:

```bash
just run --release --example <example name>
```

Or run the examples with raw cargo commands:
```bash
RUSTFLAGS="-Ctarget-cpu=native -Awarnings" cargo +nightly run --release --example <example name>
```

### Distributed primitives

For benchmarks of the distributed primitives, please check `hack/bench_poly_comm.sh` and `hack/bench_sumcheck.sh`.

### Distributed GKR

Run examples inside the folder `gkr/examples`.

For example, to run the POC GKR implementation (now both for local and distributed setting, feel free to make modification):
```bash
just run --release --example gkr -- --l 32 --depth 16 --width 19
```

In this command, ll represents the packing factor (we use t:=N4t := \frac{N}{4} in the paper), and the circuit size is calculated as |C|=depth×2width|C| = depth \times 2^{width}. In a consumer instance, the example provided typically completes in about 5 minutes.

The program outputs the time taken for each sub-protocol, the peak memory usage, and the actual communication cost (both incoming and outgoing data) during proof generation. This output can be redirected to a file for further analysis.

## Project layout

- `dist-primitive`: The distributed primitives, including dMSM, dPolyCommit and dSumcheck.
- `gkr`: The GKR protocol. 
- `hack`: Scripts for running the experiments.
- `mpc-net`: The network layer for the MPC.
- `secret-sharing`: The packed secret sharing scheme.

## License

This library is released under the MIT License.

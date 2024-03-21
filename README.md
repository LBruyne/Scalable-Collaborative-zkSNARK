# Collaborative-GKR

Rust implementation of the paper "Scalable Collaborative zk-SNARK: Fully Distributed Proof Generation and Malicious Security". 

The project is built upon [arkworks ecosystem](https://github.com/arkworks-rs).

## Illustration

This is a Proof-of-Concept (PoC) implementation. In the paper, we assume a peer-to-peer network for smooth operation of the MPC protocol. In experimental practice, we implemented a single peer that can be executed on a low-specification instance. We estimated the overall efficiency by calculating the computational, memory, and communication costs incurred by a node during a single proof generation process. Although we did not implement actual communication (an industrial-grade implementation could address this), we ensured that each instance accurately executed its assigned tasks, and we properly tracked for the communication overhead.

## Version

It uses a nightly version of Rust.

**WARNING**: The `stdsimd` feature has been recently removed in the Rust nightly build. If you have installed your Rust toolchain recently, you should switch to an "older" version:

```
rustup install 1.76.0
rustup default nightly-2024-02-04
```

## How to run

We offer "Rust examples" for distributed primitives and the PoC implementation of distributed GKR. For a "Rust example", if you have [`just`](https://github.com/casey/just) installed, you can run: 

```bash
just run --release --example <example name>
```

If you don't have just, execute the examples using the raw cargo commands:

```bash
RUSTFLAGS="-Ctarget-cpu=native -Awarnings" cargo +nightly run --release --example <example name>
```

### Distributed primitives

For benchmarks of the distributed primitives, please check `hack/bench_poly_comm.sh` and `hack/bench_sumcheck.sh`.

### Distributed GKR

Run the example inside the folder `gkr/examples`.

To run the comparison between PoC dGKR and GKR:
```bash
# At the root directory
just run --release --example gkr -- --l 32 --depth 16 --width 19
```

This command runs proof generation in both local and distributed settings, and you can freely modify `gkr/examples/gkr.rs` as needed. If you encounter a `Too many open files` error, adjust your environment setting with `ulimit -HSn 65536`.

In this command, $l$ represents the packing factor (we use $t := \frac{N}{4}$ in the paper), and the circuit size is calculated as $|C| = depth \times 2^{width}$.  In a consumer machine, the example provided typically completes in about 5 minutes.

The program outputs the time taken for each sub-protocol and the actual communication cost (both incoming and outgoing data) during proof generation. This output can be redirected to a file for further analysis.

## Project layout

- `dist-primitive`: The distributed primitives, including dMSM, dPolyCommit and dSumcheck.
- `gkr`: The GKR protocol. 
- `hack`: Scripts for running the experiments.
- `mpc-net`: The network layer for the MPC.
- `secret-sharing`: The packed secret sharing scheme.

## License

This library is released under the MIT License.

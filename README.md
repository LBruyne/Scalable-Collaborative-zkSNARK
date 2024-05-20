# Scalable-Collaborative-ZKP

Rust implementation of the paper "Scalable Collaborative zk-SNARK: Fully Distributed Proof Generation and Malicious Security". 

The project is built upon [arkworks ecosystem](https://github.com/arkworks-rs).

## Illustration

This is a Proof-of-Concept (PoC) implementation. In this work, we assume a peer-to-peer network for smooth operation of the MPC protocol. Each peer can be a low-specification instance (e.g., 2 vCPU and 4 GB memory is enough), where peers will be connected through LAN/WAN. The parties can collaboratively generate a ZK proof for large-scale circuits while preserving witness privacy.

We provide three kinds of modes, which are classified as follows and can be switched by adjusting Rust features:

- `leader`: A single peer that simulates its own part of the job according to the protocol. It is ensured that this instance accurately executes its assigned tasks, and we properly track the computation time and communication overhead.
- `local` and `local-multi-thread`: The local mode will simulate the distributed protocol locally, where every task is executed by a single thread. `local-multi-thread` enables multiple threads to simulate different parties locally (so your machine's number of threads should not exceed the number of parties).
- `collaborative`: This mode actually runs a distributed cluster, where different parties are deployed on different machines and collaborate together to generate a proof. We provide some scripts to deploy such a cluster.

## Version

It uses a nightly version of Rust.

**WARNING**: The `stdsimd` feature has been recently removed in the Rust nightly build. If you have installed your Rust toolchain recently, you should switch to an "older" version:

```
rustup install 1.76.0
rustup default nightly-2024-02-04
```

## How to run

### Distributed primitives

We offer "Rust examples" for distributed primitives under the `dist-primitive` folder. If you have [`just`](https://github.com/casey/just) installed, you can run:

```bash
just run --release --example <example name> <args>
```

If you don't have just, execute the examples using the raw cargo commands:

```bash
RUSTFLAGS="-Ctarget-cpu=native -Awarnings" cargo +nightly run --release --example <example name> <args>
```

For example, to run a collaborative sumcheck protocol in `leader` mode, run:

```bash
just run --release --example sumcheck -F leader -l 32 -n 20
# WARNING: If you encounter a `Too many open files` error, please adjust your environment setting with `ulimit -HSn 65536` 
```

This simulate a leader's task in a cluster where 128 parties engage in and the variable number of sumcheck is $2^{20}$. To further benchmark the distributed primitives described in the paper, please check `hack/bench_poly_comm.sh` and `hack/bench_sumcheck.sh`. We only provide commands for leader mode. To switch modes, try different features. You can change to collaborative mode if you have enough well-connected hardware resources.

### Distributed ZKPs

We offer implementation and examples for collaborative Libra (in the `gkr` crate) and collaborative HyperPlonk (in the `hyperplonk` crate). For example, to run the comparison between local Libra and collaborative Libra:

```bash
# At the root directory
just run --release --example gkr -F leader -- --l 32 --d 16 --w 16
```

In this command, $l$ represents the packing factor, and the circuit size is calculated as $|C| = d \times 2^{w}$.

The program outputs the time taken for the leader running the protocol and the actual communication cost (both incoming and outgoing data) during the proof generation. This output can be redirected to a file for further analysis.

### Benchmark

To run a benchmark with packing factor $l$ you need $l\times 4$ servers. There are two scripts located in the `hack/run-hyperplonk` and  `hack/run-gkr` folder, to run the benchmark for HyperPlonk and GKR, respectively. In order to set up the benchmarks, you have to:

1. Filling the addresses in `hack/run-hyperplonk/ip_addresses.txt` and `hack/run-gkr/ip_addresses.txt` with IP address publicly accessible from where you run the scripts. Make sure the files end with a new line.
2. Filling the addresses in `network-address` with IP address accessible from the servers (private IP address). Make sure you have a proper amount of addresses in each file. Make sure the files end with a new line.
3. `cd` to `hack/run-hyperplonk` or  `hack/run-gkr`, and run following commands:
    ```bash
    mkdir output
    ./handle_server.sh ./ip_addresses.txt
    ```
4. You shall see results in `output` folder.

To run the local benchmarks, simply run examples `gkr` and `hyperplonk`.

## Project layout

- `dist-primitive`: The distributed primitives.
- `gkr`: The GKR protocol. 
- `gkr`: The Hyperplonk protocol. 
- `hack`: Scripts for running the experiments.
- `mpc-net`: The network layer for the MPC.
- `secret-sharing`: The packed secret sharing scheme.

## License

This library is released under the MIT License.

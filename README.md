# Scalable-Collaborative-zk-SNARK

Rust implementation of the paper "Scalable Collaborative zk-SNARK". 

The project is built upon [arkworks ecosystem](https://github.com/arkworks-rs).

## Illustration

This is a Proof-of-Concept (PoC) implementation. In this work, we assume a peer-to-peer network for smooth operation of the MPC protocol. Each peer can be a low-specification instance (e.g., 2 vCPU and 4 GB memory is enough), where peers will be connected through LAN/WAN. The parties can collaboratively generate a ZK proof for large-scale circuits while preserving witness privacy.

We provide three kinds of modes, which are classified as follows and can be switched by adjusting Rust features:

- `benchmark`: This mode actually runs a *distributed* cluster, where different parties are deployed on different machines and collaborate together to generate a proof. We provide some scripts to deploy such a cluster, and our benchmark is based on this mode.
- `leader`: A single peer *locally* simulates its own part of the proof generation according to the protocol. It is ensured that this instance accurately executes its assigned tasks, and we properly track the computation time and communication overhead. Since every peer undertakes the same workload in our work, it is a promising way to evaluate the complexities in one server.
- `local` and `local-multi-thread`: The `local` mode will simulate the distributed cluster *locally*, where every task is executed by a single thread in a sequence. `local-multi-thread` enables multiple threads to simulate different parties locally and these threads will run at the same time to simulate different parites (so your machine's number of threads should not less than the parties count).

## Version

It uses a nightly version of Rust.

```
rustup 1.27.1 (54dd3d00f 2024-04-24)
cargo 1.80.0-nightly (05364cb2f 2024-05-03)
```

**WARNING**: The `stdsimd` feature has been recently removed in the Rust nightly build. If you have installed your Rust toolchain recently, you should switch to an "older" version.

## How to run

### Benchmark

The benchmarks are based on the aformentioned `benchmark` mode. To run a benchmark with packing factor $l$ you need $l\times 4$ servers. If you have an additional jump server for your cluster, things are easier. There is a script located at `hack/prepare-server.sh` for preparing the jump server for the benchmarks. For servers communication, you will need a ip address file filled with server ip like this:
```
192.168.1.2
192.168.1.3
192.168.1.4
192.168.1.5,

```
Make sure it ends with a new line, and the ip of jump server as the input to the script. Notably there are a few things to tweak:

1. You need to change the username and identity file in the script.
2. Be sure to check the `pack.sh` scripts and see if any path is not correct for your system. 
3. Remove the zkSaaS-related lines if they are not available
4. Change the directories if you don't like them
5. Change the ports if they are not available

We strongly advise you run the script or you may have to read through the script yourself to understand how the scripts work and how to manually set up the addresses. To run the benchmark for HyperPlonk and GKR, respectively, you have to:

1. Go to the jump server
2. `cd` to `hyperplonk` or  `gkr`
3. Change the benchmark scales in `handle_server.sh`, and run following commands:
    ```bash
    ./handle_server.sh ./ip_addresses.txt
    ```
4. You shall see results in `output` folder. We also provide a `read_data.ipynb` script for reading these output into .csv files.

### Distributed primitives

We also offer Rust examples for distributed primitives under the `dist-primitive` folder. If you have [`just`](https://github.com/casey/just) installed, you can run:

```bash
just run --release --example <example name> <args>
```

If you don't have just, execute the examples using the raw cargo commands:

```bash
RUSTFLAGS="-Ctarget-cpu=native -Awarnings" cargo +nightly run --release --example <example name> <args>
```

For example, to run a collaborative sumcheck protocol in a local `leader` mode, run:

```bash
just run --release --example sumcheck -F leader -- --l 32 --n 20
# WARNING: If you encounter a `Too many open files` error, please adjust your environment setting with `ulimit -HSn 65536` 
```

This command will locally simulate one server's task in a cluster where $128=l*4$ parties engage in and the input number of sumcheck is $2^{20}$. 

To further benchmark the distributed primitives described in the paper, please check the scripts under `hack` folder (e.g., `hack/bench_sumcheck.sh`). We only provide commands for leader mode. To switch modes, try different Rust features. You can change to `benchmark` mode if you have enough hardware resources.

### Distributed ZKPs

We offer implementation and examples for collaborative Libra (in the `gkr` crate) and collaborative HyperPlonk (in the `hyperplonk` crate). For example, to run the comparison between local Libra and collaborative Libra:

```bash
# At the root directory
just run --release --example gkr -F leader -- --l 32 --d 16 --w 16
```

In this command, $l$ represents the packing factor, and the circuit size is calculated as $n = d \times 2^{w}$.

The program outputs the time taken for the a server running the protocol and its actual communication cost (both incoming and outgoing data) during the proof generation. This output can be redirected to a file for further analysis. To switch modes, try different Rust features. You can change to `benchmark` mode if you have enough hardware resources.

## Project layout

- `dist-primitive`: The distributed primitives.
- `gkr`: The collborative GKR protocol. 
- `hyperplonk`: The collborative Hyperplonk protocol. 
- `hack`: Scripts for running the experiments.
- `mpc-net`: The network layer for the MPC.
- `secret-sharing`: The packed secret sharing scheme.

## License

This library is released under the MIT License.

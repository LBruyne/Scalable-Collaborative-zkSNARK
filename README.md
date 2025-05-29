# Scalable-Collaborative-zk-SNARK

Rust implementation of the paper "[Scalable Collaborative zk-SNARK and its Application to Fully Distributed Proof Delegation](https://eprint.iacr.org/2024/940)".

**⚠️ WARNING**: This is an academic proof-of-concept prototype and has **not** undergone a thorough code review. It is **NOT suitable** for production use. The benchmarks are intended primarily to measure time, memory, and communication complexities; **correctness of the output proofs is not guaranteed**.

**🔗 Acknowledgment**: This project is built on top of the [arkworks ecosystem](https://github.com/arkworks-rs). Several crates were adapted from and are credited to [collaborative-zksnark](https://github.com/alex-ozdemir/collaborative-zksnark) and [zkSaaS](https://github.com/guruvamsi-policharla/zksaas).

## Overview 

- [`config/`](config): Some configuration files and parameters.
- [`dist-primitive/`](dist-primitive): Implementation of collaborative and distributed primitives introduced in the paper.
- [`hack/`](hack): Scripts for running the code and benchmarks.
- [`hyperplonk/`](hyperplonk): Proof-of-concept implementation of collaborative [HyperPlonk](https://eprint.iacr.org/2022/1355), including the monolithic prover.
- [`mpc-net/`](mpc-net): Implementation of an MPC network for inter-party communication.
- [`secret-sharing/`](secret-sharing): Implementation of the Packed Secret Sharing (PSS) scheme, supporting both finite field and elliptic curve group elements.

## Illustration

<!-- **Artifact Evaluation**: For artifact evaluation reviewers, please jump to [How to Benchmark](#benchmark). -->

In this work, we assume multiparty is connected through a peer-to-peer network for smooth operation of the MPC protocol. Each peer can be a low-end instance (e.g., 2 vCPU and 4 GB memory is enough). Upon receiving the secret-shared witness, the parties collaborate to generate a ZK proof for large-scale circuits while preserving witness privacy.

Ideally, the code should be executed in a distributed network environment with 16/32/64/128 servers. However, it is not always feasible for developers to conduct tests on such a large number of machines. Therefore, we provide three operation modes, which are categorized as follows and can be switched by adjusting the Rust [features](./hyperplonk/Cargo.toml):

- `benchmark`: This mode actually runs a *distributed* network, where different parties are deployed on different machines and collaborate together to generate a proof. We provide some scripts to deploy such a cluster, and our benchmark is based on this mode. See benchmark instructions [here](#benchmark). This mode actually communicates through a *LAN/WAN* network.
- `leader`: A single peer *locally* simulates its own part of the proof generation according to the protocol. It is ensured that this peer accurately executes its assigned tasks, and we properly track the computation time and communication overhead. Since in the paper, every peer undertakes the same workload, it is a promising way to evaluate the complexities in one server. This mode does NOT actually communicate through a network.
- `local` and `local-multi-thread`: The `local` mode simulates the distributed cluster *locally*, where all tasks are executed sequentially by a single thread. This means, in each protocol, the thread performs the computation for one party and then proceeds to the next. As a result, the total execution time should be divided by the number of parties to approximate the actual runtime in a real distributed setting.
The `local-multi-thread` mode enables multiple threads to simulate different parties locally, with each thread running concurrently to represent a separate party. Therefore, the number of available threads on your machine should not be less than the number of parties. However, we note that the performance estimation in this multi-threaded mode is often inaccurate. 
This mode actually communicates through a *Local* network.

## Version

It uses a nightly version of Rust.

```
rustup 1.27.1 (54dd3d00f 2024-04-24)
cargo 1.80.0-nightly (05364cb2f 2024-05-03)
```

**WARNING**: The `stdsimd` feature has been recently removed in the Rust nightly build. If you have installed your Rust toolchain recently, you should switch to an "older" version.

## How to run

### Benchmark

The benchmarks are based on the `benchmark` mode. A crucial parameter is $l$, which represents the packing factor as defined in the paper. To run a benchmark with packing factor $l$, you need $l \times 8$ servers. The expected speedup is approximately between $l$ and $2l$ times.

<!-- **Artifact Evaluation**: We understand that it may be difficult for reviewers to access a large number of servers to reproduce the results in the `benchmark` mode, although the results presented in the paper were obtained using this mode. Therefore, you can use the `local` mode to simulate the results. Remember to divide the total execution time by the number of servers $N$ to estimate the actual running time. -->

If you have an additional *jump server* for your cluster, deploying the cluster becomes easier. A script is provided at `hack/prepare-server.sh` to prepare the jump server for running benchmarks. For inter-server communication, you will need an IP address file containing the list of server IPs in the following format:
```
192.168.1.2
192.168.1.3
192.168.1.4
192.168.1.5

```
Make sure the file ends with a newline, and provide the jump server's IP address as an input to the script. Notably, there are a few things to tweak:

1. You need to change the username and identity file in the script.
2. Be sure to check the `pack.sh` scripts and see if any path is not correct for your system. 
3. Remove the zkSaaS-related lines if they are not available
4. Change the directories if you don't like them
5. Change the ports if they are not available
6. You can use the `tc` command in a Linux machine to control the network speed to simulate LAN/WAN.

There are 4 benchmarks available. They are:
1. Collaborative and monolithic Hyperplonk (for general circuits) §5.2, Fig. 3, Tab. 2
2. Collaborative Hyperplonk (for data-parallel circuits) §5.3, Tab. 4
3. Collaborative permcheck (with prodcheck) §4.3, Tab. 5
4. Collaborative permcheck (improved) §5.1, Tab. 5
 
The benchmark of zkSaaS can be found [here](https://github.com/guruvamsi-policharla/zksaas), and it can be executed by following the instructions provided in that repository.

We strongly advise you run the script, or you may have to read through the script yourself to understand how the scripts work and how to manually set up the addresses. To run the benchmarks, you have to:

1. Go to the jump server
2. `cd` to the desired bench
3. Change the benchmark scales in `handle_server.sh`, and run following commands:
    ```bash
    ./handle_server.sh ./ip_addresses.txt
    ```
4. You shall see results in `output` folder. We also provide a `read_data.ipynb` script for reading these output into .csv files.

### Collaborative \& Distributed primitives

We also offer Rust examples for collaborative and distributed primitives under the `dist-primitive` folder. If you have [`just`](https://github.com/casey/just) installed, you can run:

```bash
just run --release --example <example name> <args>
```

If you don't have just, execute the examples using the raw cargo commands:

```bash
RUSTFLAGS="-Ctarget-cpu=native -Awarnings" cargo +nightly run --release --example <example name> <args>
```

For example, to run a collaborative sumcheck protocol in a `leader` mode (only one party executes its job locally), run:

```bash
just run --release --example sumcheck -F leader -- --l 16 --n 20
# WARNING: If you encounter a `Too many open files` error, please adjust your environment setting with `ulimit -HSn 65536` 
```

This command locally simulates the task of a single server in a network where $128 = l \times 8$ parties participate, and the input size for the sumcheck protocol is $2^{20}$. The output will indicate that the leader's running time is approximately $\frac{1}{16}$ of that of the local prover.

Also you can run:
```bash
just run --release --example sumcheck -F local -- --l 16 --n 20
```

This command initiates a local network to perform the same task. The output time should be divided by $N = 128 = 8 \times 16$ to estimate the simulated execution time for each party.

To further benchmark the collaborative primitives in a large scale, please check the scripts under `hack` folder (e.g., `hack/bench_sumcheck.sh`). We only provide commands for leader mode. To switch modes, try different Rust features. You can also change to `benchmark` mode if you have enough hardware resources.

### Collaborative ZKPs

We offer implementation and examples for collaborative HyperPlonk (in the `hyperplonk` crate). For example, to run the comparison between monolithic Hyperplonk and collaborative Hyperplonk:

```bash
# At the root directory
just run --release --example hyperplonk -F leader -- --l 16 --n 15
```

In this command, $l$ represents the packing factor, and the circuit size is $2^{n}$.

The program outputs the time taken for the a server running the protocol and its actual communication cost (both incoming and outgoing data) during the proof generation. This output can be redirected to a file for further analysis.

## License

This library is released under the MIT License.

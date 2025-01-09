use ark_ec::{bls12::Bls12, pairing::Pairing};
use ark_std::UniformRand;
use clap::Parser;
use dist_primitive::dacc_product::c_acc_product_and_share;
use dist_primitive::dacc_product::d_acc_product;
use dist_primitive::random_evaluations;
use hyperplonk::dhyperplonk::PackedProvingParameters;
use mpc_net::{end_timer, start_timer};
use mpc_net::{LocalTestNet, MPCNet, MultiplexedStreamID};
use rayon::prelude::*;
use secret_sharing::pss::PackedSharingParams;
use std::hint::black_box;

type Fr = <Bls12<ark_bls12_381::Config> as Pairing>::ScalarField;

#[derive(Parser)]
struct Cli {
    /// The packing size, should be 1/4 of the party size as well as a power of 2.
    #[arg(long)]
    l: usize,
    /// log2 of the total number of variables.
    #[arg(long)]
    n: usize,
}

#[cfg_attr(feature = "single_thread", tokio::main(flavor = "current_thread"))]
#[cfg_attr(not(feature = "single_thread"), tokio::main)]
async fn main() {
    let args = Cli::parse();

    d_prodcheck_bench(args.n, args.l).await;
    c_prodcheck_bench(args.n, args.l).await;
}

/// This benchmark just runs the leader's part of the protocol without any networking involved.
#[cfg(feature = "leader")]
async fn c_prodcheck_bench(n: usize, l: usize) {
    // Distributed

    use dist_primitive::dsumcheck::c_sumcheck_product;

    let pp = PackedSharingParams::<Fr>::new(l);
    let pk = PackedProvingParameters::<Bls12<ark_bls12_381::Config>>::new(n, l, &pp);
    let gate_count = 2usize.pow(n as u32);
    // Prepare shares and masks
    // let x: Vec<_> = random_evaluations(gate_count / l);
    let mask: Vec<_> = random_evaluations(gate_count / l);
    let unmask0: Vec<_> = random_evaluations(gate_count / l);
    let unmask1: Vec<_> = random_evaluations(gate_count / l);
    let unmask2: Vec<_> = random_evaluations(gate_count / l);

    let net = LocalTestNet::new_local_testnet(l * 8).await.unwrap();
    let distributed = start_timer!("C product check");
    let num = (0..gate_count/pp.l)
        .map(|i| {
            (pk.a_evals[i] + pk.beta * pk.ssigma_a[i] + pk.gamma)
                * (pk.b_evals[i] + pk.beta * pk.ssigma_b[i] + pk.gamma)
                * (pk.c_evals[i] + pk.beta * pk.ssigma_c[i] + pk.gamma)
        })
        .collect();
    let den = (0..gate_count/pp.l)
        .map(|i| {
            (pk.a_evals[i] + pk.beta * pk.sid[i] + pk.gamma)
                * (pk.b_evals[i] + pk.beta * pk.sid[i] + pk.gamma)
                * (pk.c_evals[i] + pk.beta * pk.sid[i] + pk.gamma)
        })
        .collect();
    let fs = vec![num, den];

    let mut wire_identity = Vec::new();
    for evaluations in &fs {
        let mut proofs = Vec::new();
        let mut commits = Vec::new();
        // Compute V
        let (vx0, vx1, v1x) = c_acc_product_and_share(
            evaluations,
            &mask,
            &unmask0,
            &unmask1,
            &unmask2,
            &pp,
            &net.get_leader(),
            MultiplexedStreamID::Zero,
        )
        .await
        .unwrap();
        // Commit
        let com_v0x = pk
            .c_commitment
            .c_commit(
                &vec![evaluations.clone()],
                &pp,
                &net.get_leader(),
                MultiplexedStreamID::Zero,
            )
            .await
            .unwrap()[0];
        let com_v1x = pk
            .c_commitment
            .c_commit(
                &vec![v1x.clone()],
                &pp,
                &net.get_leader(),
                MultiplexedStreamID::Zero,
            )
            .await
            .unwrap()[0];
        // Open
        commits.push((
            com_v0x,
            pk.c_commitment
                .c_open(
                    &evaluations,
                    &pk.challenge,
                    &pp,
                    &net.get_leader(),
                    MultiplexedStreamID::Zero,
                )
                .await
                .unwrap(),
        ));
        commits.push((
            com_v1x,
            pk.c_commitment
                .c_open(
                    &v1x,
                    &pk.challenge,
                    &pp,
                    &net.get_leader(),
                    MultiplexedStreamID::Zero,
                )
                .await
                .unwrap(),
        ));
        // Sumcheck for F(x)=eq(x)*(v1x-vx0*vx1).
        proofs.push(
            c_sumcheck_product(
                &pk.eq,
                &v1x,
                &pk.challenge,
                &pp,
                &net.get_leader(),
                MultiplexedStreamID::Zero,
            )
            .await
            .unwrap(),
        );
        proofs.push(
            c_sumcheck_product(
                &pk.eq,
                &vx0,
                &pk.challenge,
                &pp,
                &net.get_leader(),
                MultiplexedStreamID::Zero,
            )
            .await
            .unwrap(),
        );
        proofs.push(
            c_sumcheck_product(
                &vx0,
                &vx1,
                &pk.challenge,
                &pp,
                &net.get_leader(),
                MultiplexedStreamID::Zero,
            )
            .await
            .unwrap(),
        );
        wire_identity.push((proofs, commits));
    }
    end_timer!(distributed);
    println!("Comm: {:?}", net.get_leader().get_comm());
}

/// This benchmark runs the protocol in a simulation mode, all parties are involved with actual LOCAL communication.
/// Defaultly the benchmark is to run in a multi-threaded environment.
/// When #[tokio::main(flavor = "current_thread")] feature is enabled, the benchmark is set to run in a single thread.
#[cfg(not(feature = "leader"))]
async fn c_prodcheck_bench(n: usize, l: usize) {
    // Distributed
    use dist_primitive::dsumcheck::c_sumcheck_product;

    let pp = PackedSharingParams::<Fr>::new(l);
    let pk = PackedProvingParameters::<Bls12<ark_bls12_381::Config>>::new(n, l, &pp);
    let gate_count = 2usize.pow(n as u32);
    // Prepare shares and masks
    // let x: Vec<_> = random_evaluations(gate_count / l);
    let mask: Vec<_> = random_evaluations(gate_count / l);
    let unmask0: Vec<_> = random_evaluations(gate_count / l);
    let unmask1: Vec<_> = random_evaluations(gate_count / l);
    let unmask2: Vec<_> = random_evaluations(gate_count / l);

    let net = LocalTestNet::new_local_testnet(l * 8).await.unwrap();
    let distributed = start_timer!("C product check");
    let _ = net
        .simulate_network_round(
            (x, mask, unmask0, unmask1, unmask2),
            move |net, (x, mask, unmask0, unmask1, unmask2)| async move {
                let pp = PackedSharingParams::<Fr>::new(l);

                let num = (0..gate_count)
                    .map(|i| {
                        (pk.a_evals[i] + pk.beta * pk.ssigma_a[i] + pk.gamma)
                            * (pk.b_evals[i] + pk.beta * pk.ssigma_b[i] + pk.gamma)
                            * (pk.c_evals[i] + pk.beta * pk.ssigma_c[i] + pk.gamma)
                    })
                    .collect();
                let den = (0..gate_count)
                    .map(|i| {
                        (pk.a_evals[i] + pk.beta * pk.sid[i] + pk.gamma)
                            * (pk.b_evals[i] + pk.beta * pk.sid[i] + pk.gamma)
                            * (pk.c_evals[i] + pk.beta * pk.sid[i] + pk.gamma)
                    })
                    .collect();
                let fs = vec![num, den];

                let mut wire_identity = Vec::new();
                for evaluations in &fs {
                    let mut proofs = Vec::new();
                    let mut commits = Vec::new();
                    // Compute V
                    let (vx0, vx1, v1x) = c_acc_product_and_share(
                        evaluations,
                        &mask,
                        &unmask0,
                        &unmask1,
                        &unmask2,
                        &pp,
                        &net,
                        MultiplexedStreamID::Zero,
                    )
                    .await
                    .unwrap();
                    // Commit
                    let com_v0x = pk
                        .c_commitment
                        .c_commit(
                            &vec![evaluations.clone()],
                            &pp,
                            &net,
                            MultiplexedStreamID::Zero,
                        )
                        .await
                        .unwrap()[0];
                    let com_v1x = pk
                        .c_commitment
                        .c_commit(&vec![v1x.clone()], &pp, &net, MultiplexedStreamID::Zero)
                        .await
                        .unwrap()[0];
                    // Open
                    commits.push((
                        com_v0x,
                        pk.c_commitment
                            .c_open(
                                &evaluations,
                                &pk.challenge,
                                &pp,
                                &net,
                                MultiplexedStreamID::Zero,
                            )
                            .await
                            .unwrap(),
                    ));
                    commits.push((
                        com_v1x,
                        pk.c_commitment
                            .c_open(&v1x, &pk.challenge, &pp, &net, MultiplexedStreamID::Zero)
                            .await
                            .unwrap(),
                    ));
                    // Sumcheck for F(x)=eq(x)*(v1x-vx0*vx1).
                    proofs.push(
                        c_sumcheck_product(
                            &pk.eq,
                            &v1x,
                            &pk.challenge,
                            &pp,
                            &net,
                            MultiplexedStreamID::Zero,
                        )
                        .await
                        .unwrap(),
                    );
                    proofs.push(
                        c_sumcheck_product(
                            &pk.eq,
                            &vx0,
                            &pk.challenge,
                            &pp,
                            &net,
                            MultiplexedStreamID::Zero,
                        )
                        .await
                        .unwrap(),
                    );
                    proofs.push(
                        c_sumcheck_product(
                            &vx0,
                            &vx1,
                            &pk.challenge,
                            &pp,
                            &net,
                            MultiplexedStreamID::Zero,
                        )
                        .await
                        .unwrap(),
                    );
                    wire_identity.push((proofs, commits));
                }

                if net.is_leader() {
                    println!("Comm: {:?}", net.get_comm());
                }
            },
        )
        .await;
    end_timer!(distributed);
    println!("Comm: {:?}", net.get_leader().get_comm());
}

/// This benchmark just runs the leader's part of the protocol without any networking involved.
#[cfg(feature = "leader")]
async fn d_prodcheck_bench(n: usize, l: usize) {
    // Distributed

    use dist_primitive::dsumcheck::{d_sumcheck_product, sumcheck_product};
    let pp = PackedSharingParams::<Fr>::new(l);
    let pk = PackedProvingParameters::<Bls12<ark_bls12_381::Config>>::new(n-2, l, &pp);
    // Prepare shares and masks
    let x: Vec<_> = random_evaluations::<Fr>(2usize.pow(n as u32) / pp.n);

    let net = LocalTestNet::new_local_testnet(l * 8).await.unwrap();
    let distributed = start_timer!("d product check");
    let mut wiring_commits = Vec::new();
    let mut wiring_proofs = Vec::new();
    let mut wiring_opens = Vec::new();
    let (subtree, top) = d_acc_product(&x, &net.get_leader(), MultiplexedStreamID::Zero)
        .await
        .unwrap();
    // 2.e.1 zerocheck on p(x) = h(x) - v(0,x)
    // Commit v0x
    wiring_commits.push(
        pk.d_commitment
            .d_commit(&x, &net.get_leader(), MultiplexedStreamID::Zero)
            .await
            .unwrap(),
    );

    // sumcheck product for p and eq
    wiring_proofs.push(
        d_sumcheck_product(
            &x,
            &pk.eq_r2_p,
            &pk.challenge_r2,
            &net.get_leader(),
            MultiplexedStreamID::Zero,
        )
        .await
        .unwrap(),
    );
    // Open p
    wiring_opens.push(
        pk.d_commitment
            .d_open(
                &x,
                &pk.challenge_r2,
                &net.get_leader(),
                MultiplexedStreamID::Zero,
            )
            .await
            .unwrap(),
    );
    wiring_opens.push(
        pk.d_commitment
            .d_open(
                &pk.eq_r2_p,
                &pk.challenge_r2,
                &net.get_leader(),
                MultiplexedStreamID::Zero,
            )
            .await
            .unwrap(),
    );

    // 2.e.2 zerocheck on q(x) = v(1,x) - v(x,0) * v(x,1)
    // We are literally running l sumchecks, let's get these three v first
    let v1x: Vec<_> = subtree
        .iter()
        .skip(subtree.len() / 2)
        .map(Fr::clone)
        .collect();
    let vx0: Vec<_> = subtree.iter().step_by(2).map(Fr::clone).collect();
    let vx1: Vec<_> = subtree.iter().skip(1).step_by(2).map(Fr::clone).collect();

    // Compute u = (v(1,x) - v(x,0) * v(x,1)) * eq(x)
    let u: Vec<_> = v1x
        .iter()
        .zip(vx0.iter().zip(vx1.iter().zip(pk.eq_r2_p.iter())))
        .map(|(a, (b, (c, d)))| (*a - *b * *c) * *d)
        .collect();
    wiring_commits.push(
        pk.d_commitment
            .d_commit(&u, &net.get_leader(), MultiplexedStreamID::Zero)
            .await
            .unwrap(),
    );

    // We then run a series of sumchecks
    let s = pp.n.trailing_zeros() as usize;
    let mut current_v1x = v1x[..v1x.len() / 2].to_vec();
    let mut current_vx0 = vx0[..vx0.len() / 2].to_vec();
    let mut current_vx1 = vx1[..vx1.len() / 2].to_vec();
    let mut current_eq = pk.eq_r2_p[..pk.eq_r2_p.len() / 2].to_vec();
    for i in 1..n - s + 1 {
        // dsumcheck the first half of current_u
        // This is actually 50% more costly
        wiring_proofs.push(
            d_sumcheck_product(
                &current_v1x,
                &current_eq,
                &pk.challenge_r2[i..].to_vec(),
                &net.get_leader(),
                MultiplexedStreamID::Zero,
            )
            .await
            .unwrap(),
        );
        wiring_proofs.push(
            d_sumcheck_product(
                &current_vx0,
                &current_vx1,
                &pk.challenge_r2[i..].to_vec(),
                &net.get_leader(),
                MultiplexedStreamID::Zero,
            )
            .await
            .unwrap(),
        );
        current_v1x = current_v1x[current_v1x.len() / 2..].to_vec();
        current_vx0 = current_vx0[current_vx0.len() / 2..].to_vec();
        current_vx1 = current_vx1[current_vx1.len() / 2..].to_vec();
        current_eq = current_eq[current_eq.len() / 2..].to_vec();
    }

    // Next we run a similar open procedure
    let mut current_u = u[..u.len() / 2].to_vec();
    for i in 1..n - s + 1 {
        // open the first half of current_u
        wiring_opens.push(
            pk.d_commitment
                .d_open(
                    &current_u,
                    &pk.challenge_r2[i..].to_vec(),
                    &net.get_leader(),
                    MultiplexedStreamID::Zero,
                )
                .await
                .unwrap(),
        );
        current_u = current_u[current_u.len() / 2..].to_vec();
    }
    if let Some(leader_tree) = top {
        // Compute corresponding v1x, vx0, vx1
        let v1x: Vec<_> = leader_tree
            .iter()
            .skip(leader_tree.len() / 2)
            .map(Fr::clone)
            .collect();
        let vx0: Vec<_> = leader_tree.iter().step_by(2).map(Fr::clone).collect();
        let vx1: Vec<_> = leader_tree
            .iter()
            .skip(1)
            .step_by(2)
            .map(Fr::clone)
            .collect();
        let u: Vec<_> = v1x
            .iter()
            .zip(vx0.iter().zip(vx1.iter().zip(pk.eq_r2_p.iter())))
            .map(|(a, (b, (c, d)))| (*a - *b * *c) * *d)
            .collect();
        wiring_proofs.push(sumcheck_product(
            &v1x,
            &pk.eq_top_p,
            &pk.challenge_r2[..s].to_vec(),
        ));
        wiring_proofs.push(sumcheck_product(&vx0, &vx1, &pk.challenge_r2[..s].to_vec()));
        wiring_opens.push(pk.d_commitment.open(&u, &pk.challenge_r2[..s].to_vec()));
    }
    end_timer!(distributed);
    println!("Comm: {:?}", net.get_leader().get_comm());
}

/// This benchmark runs the protocol in a simulation mode, all parties are involved with actual LOCAL communication.
/// Defaultly the benchmark is to run in a multi-threaded environment.
/// When #[tokio::main(flavor = "current_thread")] feature is enabled, the benchmark is set to run in a single thread.
#[cfg(not(feature = "leader"))]
async fn d_prodcheck_bench(n: usize, l: usize) {
    // Distributed
    let pp = PackedSharingParams::<Fr>::new(l);
    // Prepare shares and masks
    let x: Vec<Fr> = (0..(2usize.pow(n as u32) / l))
        .into_par_iter()
        .map(|_| Fr::rand(&mut ark_std::test_rng()))
        .collect();
    let mask: Vec<Fr> = (0..(2usize.pow(n as u32) / l))
        .into_par_iter()
        .map(|_| Fr::rand(&mut ark_std::test_rng()))
        .collect();
    let unmask0: Vec<Fr> = (0..(2usize.pow(n as u32) / l))
        .into_par_iter()
        .map(|_| Fr::rand(&mut ark_std::test_rng()))
        .collect();
    let unmask1: Vec<Fr> = (0..(2usize.pow(n as u32) / l))
        .into_par_iter()
        .map(|_| Fr::rand(&mut ark_std::test_rng()))
        .collect();
    let unmask2: Vec<Fr> = (0..(2usize.pow(n as u32) / l))
        .into_par_iter()
        .map(|_| Fr::rand(&mut ark_std::test_rng()))
        .collect();

    let net = LocalTestNet::new_local_testnet(l * 8).await.unwrap();
    let distributed = start_timer!("C product check");
    let _ = net
        .simulate_network_round(
            (
                x_share,
                mask_share,
                unmask0_share,
                unmask1_share,
                unmask2_share,
            ),
            move |net, (x, mask, unmask0, unmask1, unmask2)| async move {
                let pp = PackedSharingParams::<Fr>::new(l);

                let _ = c_acc_product_and_share(
                    &x,
                    &mask,
                    &unmask0,
                    &unmask1,
                    &unmask2,
                    &pp,
                    &net,
                    MultiplexedStreamID::Zero,
                )
                .await
                .unwrap();

                if net.is_leader() {
                    println!("Comm: {:?}", net.get_comm());
                }
            },
        )
        .await;
    end_timer!(distributed);
    println!("Comm: {:?}", net.get_leader().get_comm());
}

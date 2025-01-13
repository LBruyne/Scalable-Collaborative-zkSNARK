use std::hint::black_box;

use ark_ec::pairing::Pairing;
use ark_ff::fields::Field;
use ark_std::UniformRand;
use dist_primitive::dacc_product::{c_acc_product, d_acc_product};
use dist_primitive::degree_reduce::degree_reduce_many;
use dist_primitive::dsumcheck::{d_sumcheck, d_sumcheck_product};
use dist_primitive::mle::d_fix_variable;
use dist_primitive::random_evaluations;
use dist_primitive::{
    dacc_product::c_acc_product_and_share,
    dpoly_comm::{PolynomialCommitment, PolynomialCommitmentCub},
    dsumcheck::{c_sumcheck_product, sumcheck_product},
    mle::fix_variable,
    utils::serializing_net::MPCSerializeNet,
};
use mpc_net::{end_timer, start_timer};
use mpc_net::{MPCNetError, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;

// Those fields with _p suffixes are plain and distributed values, those without are shares.
#[derive(Clone, Debug)]
pub struct PackedProvingParameters<E: Pairing> {
    pub V: Vec<E::ScalarField>,
    pub a_evals: Vec<E::ScalarField>,
    pub b_evals: Vec<E::ScalarField>,
    pub c_evals: Vec<E::ScalarField>,
    pub I: Vec<E::ScalarField>,
    pub S1: Vec<E::ScalarField>,
    pub S2: Vec<E::ScalarField>,
    pub I_p: Vec<E::ScalarField>,
    pub S1_p: Vec<E::ScalarField>,
    pub S2_p: Vec<E::ScalarField>,
    pub ssigma: Vec<E::ScalarField>,
    pub ssigma_p: Vec<E::ScalarField>,
    pub ssigma_a: Vec<E::ScalarField>,
    pub ssigma_b: Vec<E::ScalarField>,
    pub ssigma_c: Vec<E::ScalarField>,
    pub sid: Vec<E::ScalarField>,
    pub sid_p: Vec<E::ScalarField>,
    // Challenges
    pub eq: Vec<E::ScalarField>,
    pub eq_top_p: Vec<E::ScalarField>,
    pub eq_r1: Vec<E::ScalarField>,
    pub eq_r1_p: Vec<E::ScalarField>,
    pub eq_r2: Vec<E::ScalarField>,
    pub eq_r2_p: Vec<E::ScalarField>,
    pub challenge: Vec<E::ScalarField>,
    pub challenge_r1: Vec<E::ScalarField>,
    pub challenge_r2: Vec<E::ScalarField>,
    pub alpha: E::ScalarField,
    pub beta: E::ScalarField,
    pub gamma: E::ScalarField,
    pub d_commitment: PolynomialCommitment<E>,
    pub c_commitment: PolynomialCommitment<E>,
    // Masks needed
    // pub mask: Vec<E::ScalarField>,
    // pub unmask0: Vec<E::ScalarField>,
    // pub unmask1: Vec<E::ScalarField>,
    // pub unmask2: Vec<E::ScalarField>,
    // Dummies
    pub reduce_target: Vec<E::ScalarField>,
}

impl<E: Pairing> PackedProvingParameters<E> {
    pub fn new(n: usize, l: usize, pp: &PackedSharingParams<E::ScalarField>) -> Self {
        use rand::{rngs::StdRng, SeedableRng};
        let rng = &mut StdRng::from_entropy();
        let gate_count = (1 << n);
        // Shares of witness polynomial M
        let V = random_evaluations(gate_count * 4 / pp.l);
        let a_evals = fix_variable(&V, &vec![E::ScalarField::ZERO, E::ScalarField::ZERO]);
        let b_evals = fix_variable(&V, &vec![E::ScalarField::ZERO, E::ScalarField::ONE]);
        let c_evals = fix_variable(&V, &vec![E::ScalarField::ONE, E::ScalarField::ZERO]);
        // Shares of input polynomial I
        let I = random_evaluations(gate_count / pp.l);
        // plain I
        let I_p = random_evaluations(gate_count / pp.n);
        // Shares of selector polynomial Q_1, Q_2
        let S1 = random_evaluations(gate_count / pp.l);
        let S2 = random_evaluations(gate_count / pp.l);
        let S1_p = random_evaluations(gate_count / pp.n);
        let S2_p = random_evaluations(gate_count / pp.n);
        // Shares of permutation polynomial S_\sigma and identity polynomial S_id
        let ssigma: Vec<<E as Pairing>::ScalarField> = random_evaluations(gate_count * 4 / pp.l);
        let ssigma_p: Vec<<E as Pairing>::ScalarField> = random_evaluations(gate_count * 4 / pp.n);
        let ssigma_a = fix_variable(&ssigma, &vec![E::ScalarField::ZERO, E::ScalarField::ZERO]);
        let ssigma_b = fix_variable(&ssigma, &vec![E::ScalarField::ZERO, E::ScalarField::ONE]);
        let ssigma_c = fix_variable(&ssigma, &vec![E::ScalarField::ONE, E::ScalarField::ZERO]);
        let sid: Vec<<E as Pairing>::ScalarField> = random_evaluations(gate_count * 4 / pp.l);
        let sid_p: Vec<<E as Pairing>::ScalarField> = random_evaluations(gate_count * 4 / pp.n);

        // Shares of eq polynomial. For benchmarking purposes, we generate it in advance and use it repeatedly in the protocol.
        let eq = random_evaluations(gate_count / pp.l);
        let eq_top_p = random_evaluations(pp.n * 2);
        let eq_r1 = random_evaluations(gate_count * 4 / pp.l);
        let eq_r1_p = random_evaluations(gate_count * 4 / pp.n);
        let eq_r2 = random_evaluations(gate_count * 4 / pp.l);
        let eq_r2_p = random_evaluations(gate_count * 4 / pp.n);
        // Collaborative polynomial commitment. For benchmarking purposes, we reuse the parameters, which should be avoided in practice.
        let c_commitment: PolynomialCommitment<E> = PolynomialCommitmentCub::new_single(n + 2, pp);
        let d_commitment: PolynomialCommitment<E> = PolynomialCommitmentCub::new_random(n + 2);
        // Challenge for polynomial commitment opening.
        let challenge = random_evaluations(n);
        let challenge_r1 = random_evaluations(n + 2);
        let challenge_r2 = random_evaluations(n + 2);
        // Other challenges.
        let alpha = E::ScalarField::rand(rng);
        let beta = E::ScalarField::rand(rng);
        let gamma = E::ScalarField::rand(rng);
        // Dummies
        let reduce_target = random_evaluations(gate_count / pp.l / pp.l);

        PackedProvingParameters {
            V,
            a_evals,
            b_evals,
            c_evals,
            I,
            S1,
            S2,
            I_p,
            S1_p,
            S2_p,
            ssigma,
            ssigma_p,
            ssigma_a,
            ssigma_b,
            ssigma_c,
            sid,
            sid_p,
            eq,
            eq_top_p,
            eq_r1,
            eq_r1_p,
            eq_r2,
            eq_r2_p,
            challenge,
            challenge_r1,
            challenge_r2,
            alpha,
            beta,
            gamma,
            c_commitment,
            d_commitment,
            reduce_target,
        }
    }
}

pub async fn dhyperplonk<E: Pairing, Net: MPCSerializeNet>(
    n: usize, // n is the log2 of the circuit size
    pk: &PackedProvingParameters<E>,
    pp: &PackedSharingParams<E::ScalarField>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<
    (
        (
            Vec<Vec<(E::ScalarField, E::ScalarField, E::ScalarField)>>,
            Vec<(E::G1, (E::ScalarField, Vec<E::G1>))>,
        ),
        (
            Vec<
                Vec<(
                    <E as Pairing>::ScalarField,
                    <E as Pairing>::ScalarField,
                    <E as Pairing>::ScalarField,
                )>,
            >,
            Vec<<E as Pairing>::G1>,
            Vec<(<E as Pairing>::ScalarField, Vec<<E as Pairing>::G1>)>,
        ),
    ),
    MPCNetError,
> {
    let gate_count = 1 << n;

    // Now run the protocol.
    let timer_all = start_timer!("Distributed HyperPlonk", net.is_leader());

    // step 1 in figure 11
    let commit_timer = start_timer!("Commit", net.is_leader());
    let com_a = pk
        .c_commitment
        .c_commit(&vec![pk.a_evals.clone()], &pp, &net, sid)
        .await
        .unwrap()[0];
    let com_b = pk
        .c_commitment
        .c_commit(&vec![pk.b_evals.clone()], &pp, &net, sid)
        .await
        .unwrap()[0];
    let com_c = pk
        .c_commitment
        .c_commit(&vec![pk.c_evals.clone()], &pp, &net, sid)
        .await
        .unwrap()[0];
    let com_I = pk.d_commitment.d_commit(&pk.I_p, &net, sid).await.unwrap();

    let com_S1 = pk.d_commitment.d_commit(&pk.S1_p, &net, sid).await.unwrap();
    let com_S2 = pk.d_commitment.d_commit(&pk.S2_p, &net, sid).await.unwrap();

    end_timer!(commit_timer);
    // End of step 1

    let prover_timer = start_timer!("Distributed HyperPlonk Prover", net.is_leader());

    // Gate identity, step 3 in figure 11
    let gate_timer = start_timer!("Gate identity", net.is_leader());
    let mut gate_identity_proofs = Vec::new();
    let mut gate_identity_commitments = Vec::new();
    // Sumcheck F(x)=eq(x)*[q_1(x)*(a(x)+b(x))+q_2(x)*a(x)*b(x)-c(x)+I(x)]
    // In original Hyperplonk this is done with a virtual circuit.
    // We use different sumcheck product to simulate it for implementation simplicity. The computation complexity is the same.
    // Part 1
    gate_identity_proofs
        .push(c_sumcheck_product(&pk.eq, &pk.S1, &pk.challenge, pp, net, sid).await?);
    let sum_ab = pk
        .a_evals
        .iter()
        .zip(pk.b_evals.iter())
        .map(|(a, b)| *a + *b)
        .collect();
    gate_identity_proofs
        .push(c_sumcheck_product(&pk.S1, &sum_ab, &pk.challenge, pp, net, sid).await?);
    // Part 2
    gate_identity_proofs
        .push(c_sumcheck_product(&pk.eq, &pk.S2, &pk.challenge, pp, net, sid).await?);
    gate_identity_proofs
        .push(c_sumcheck_product(&pk.a_evals, &pk.b_evals, &pk.challenge, pp, net, sid).await?);
    gate_identity_proofs
        .push(c_sumcheck_product(&pk.S2, &pk.a_evals, &pk.challenge, pp, net, sid).await?);
    // Part 3
    let sum_ci = pk
        .c_evals
        .iter()
        .zip(pk.I.iter())
        .map(|(a, b)| -*a + b)
        .collect();
    gate_identity_proofs
        .push(c_sumcheck_product(&pk.eq, &sum_ci, &pk.challenge, pp, net, sid).await?);
    end_timer!(gate_timer);
    // End of step 3

    // Wiring identity, step 2 in figure 11
    let mut wiring_proofs = Vec::new();
    let mut wiring_commits = Vec::new();
    let mut wiring_opens = Vec::new();
    let wire_timer = start_timer!("Wire identity", net.is_leader());
    // 2.a compute A_s
    // A_s is the PSS of a vector with length n. Just get some random value here as local value.
    let local_s_p = random_evaluations(gate_count * 4 / net.n_parties());
    let local_s = random_evaluations(gate_count * 4 / net.n_parties() / pp.l);
    let mut s = Vec::with_capacity(gate_count * 4 / pp.l);
    for i in 0..net.n_parties() {
        // If I am the current party, send shares to others.
        let send = if i == net.party_id() as usize {
            Some(vec![local_s.clone(); net.n_parties()])
        } else {
            None
        };
        // Send to all other parties.
        let recv = net
            .dynamic_worker_receive_or_worker_send_element(send, i as u32, sid)
            .await
            .unwrap();
        #[cfg(feature = "comm")]
        {
            s.extend_from_slice(&recv);
        }

        // If no actual communication, just use the input as a placeholder.
        #[cfg(not(feature = "comm"))]
        {
            black_box(recv);
            s.extend_from_slice(&local_s);
        }
    }
    // 2.b compute com_s
    wiring_commits.push(
        pk.c_commitment
            .c_commit(&vec![s.clone()], &pp, &net, sid)
            .await
            .unwrap()[0],
    );
    // 2.c sumcheck product on V(r1), between s and V
    wiring_proofs.push(c_sumcheck_product(&s, &pk.V, &pk.challenge_r1, pp, net, sid).await?);
    // 2.d co-open V at r1 and r2, di-open s at r2
    wiring_opens.push(
        pk.c_commitment
            .c_open(&pk.V, &pk.challenge_r1, pp, net, sid)
            .await?,
    );
    wiring_opens.push(
        pk.c_commitment
            .c_open(&pk.V, &pk.challenge_r2, pp, net, sid)
            .await?,
    );
    wiring_opens.push(
        pk.d_commitment
            .d_open(&local_s_p, &pk.challenge_r2, net, sid)
            .await?,
    );
    // 2.e distributed permcheck on s and eq(r1,x)
    // d_commit s, eq(r1,x), ssigma, sid
    // s has been committed before in 2.b, omit it here
    wiring_commits.push(
        pk.d_commitment
            .d_commit(&pk.eq_r1_p, &net, sid)
            .await
            .unwrap(),
    );
    wiring_commits.push(
        pk.d_commitment
            .d_commit(&pk.ssigma_p, &net, sid)
            .await
            .unwrap(),
    );
    wiring_commits.push(
        pk.d_commitment
            .d_commit(&pk.sid_p, &net, sid)
            .await
            .unwrap(),
    );
    // prodcheck
    // Compute h
    let h_length = gate_count * 4 / net.n_parties();
    let offset = h_length * net.party_id() as usize;
    let timer = start_timer!("Local: Something", net.is_leader());
    let num: Vec<_> = (0..h_length)
        .map(|i| {
            let index = i;
            local_s_p[index] + pk.alpha * pk.sid_p[index] + pk.beta
        })
        .collect();
    let den: Vec<_> = (0..h_length)
        .map(|i| {
            let index = i;
            pk.eq_r1_p[index] + pk.alpha * pk.ssigma_p[index] + pk.beta
        })
        .collect();
    end_timer!(timer);
    // Compute h = num/den, in fact we should leave the form in upcoming steps, this is simplification
    let h_p = num.iter().zip(den.iter()).map(|(a, b)| *a / *b).collect();

    // Compute subtree of v
    let (subtree, top) = d_acc_product(&h_p, net, sid).await.unwrap();
    // 2.e.1 zerocheck on p(x) = h(x) - v(0,x)
    // Commit h, den and num
    wiring_commits.push(pk.d_commitment.d_commit(&h_p, &net, sid).await.unwrap());
    wiring_commits.push(pk.d_commitment.d_commit(&num, &net, sid).await.unwrap());

    // sumcheck product for p and eq
    wiring_proofs.push(d_sumcheck_product(&h_p, &pk.eq_r2_p, &pk.challenge_r2, net, sid).await?);
    // Open p
    wiring_opens.push(
        pk.d_commitment
            .d_open(&h_p, &pk.challenge_r2, net, sid)
            .await?,
    );
    wiring_opens.push(
        pk.d_commitment
            .d_open(&pk.eq_r2_p, &pk.challenge_r2, net, sid)
            .await?,
    );

    // 2.e.2 zerocheck on q(x) = v(1,x) - v(x,0) * v(x,1)
    // We are literally running l sumchecks, let's get these three v first
    let v1x: Vec<_> = subtree
        .iter()
        .skip(subtree.len() / 2)
        .map(<E as Pairing>::ScalarField::clone)
        .collect();
    let vx0: Vec<_> = subtree
        .iter()
        .step_by(2)
        .map(<E as Pairing>::ScalarField::clone)
        .collect();
    let vx1: Vec<_> = subtree
        .iter()
        .skip(1)
        .step_by(2)
        .map(<E as Pairing>::ScalarField::clone)
        .collect();

    // Compute (v(1,x) - v(x,0) * v(x,1)) * eq(x)
    wiring_commits.push(pk.d_commitment.d_commit(&v1x, &net, sid).await.unwrap());
    wiring_commits.push(pk.d_commitment.d_commit(&vx0, &net, sid).await.unwrap());
    wiring_commits.push(pk.d_commitment.d_commit(&vx1, &net, sid).await.unwrap());

    // We then run a series of sumchecks
    let s = net.n_parties().trailing_zeros() as usize;
    let mut current_v1x = v1x[..v1x.len() / 2].to_vec();
    let mut current_vx0 = vx0[..vx0.len() / 2].to_vec();
    let mut current_vx1 = vx1[..vx1.len() / 2].to_vec();
    let mut current_eq = pk.eq_r2_p[..pk.eq_r2_p.len() / 2].to_vec();
    let mut current_den = den[..den.len() / 2].to_vec();
    let mut current_num = num[..num.len() / 2].to_vec();
    let mut current_h = h_p[..h_p.len() / 2].to_vec();
    for i in 1..n - s + 1 {
        // dsumcheck the first half of current_u
        // This is actually 50% more costly
        wiring_proofs.push(
            d_sumcheck_product(
                &current_eq,
                &current_v1x,
                &pk.challenge_r2[i..].to_vec(),
                net,
                sid,
            )
            .await?,
        );
        wiring_proofs.push(
            d_sumcheck_product(
                &current_eq,
                &current_vx0,
                &pk.challenge_r2[i..].to_vec(),
                net,
                sid,
            )
            .await?,
        );
        wiring_proofs.push(
            d_sumcheck_product(
                &current_vx0,
                &current_vx1,
                &pk.challenge_r2[i..].to_vec(),
                net,
                sid,
            )
            .await?,
        );
        wiring_proofs.push(
            d_sumcheck_product(
                &current_eq,
                &current_den,
                &pk.challenge_r2[i..].to_vec(),
                net,
                sid,
            )
            .await?,
        );
        wiring_proofs.push(
            d_sumcheck_product(
                &current_eq,
                &current_num,
                &pk.challenge_r2[i..].to_vec(),
                net,
                sid,
            )
            .await?,
        );
        wiring_proofs.push(
            d_sumcheck_product(
                &current_h,
                &current_den,
                &pk.challenge_r2[i..].to_vec(),
                net,
                sid,
            )
            .await?,
        );

        // Next we run a similar open procedure
        wiring_opens.push(
            pk.d_commitment
                .d_open(&current_h, &pk.challenge_r2[i..].to_vec(), net, sid)
                .await?,
        );
        wiring_opens.push(
            pk.d_commitment
                .d_open(&current_v1x, &pk.challenge_r2[i..].to_vec(), net, sid)
                .await?,
        );
        wiring_opens.push(
            pk.d_commitment
                .d_open(&current_vx0, &pk.challenge_r2[i..].to_vec(), net, sid)
                .await?,
        );
        wiring_opens.push(
            pk.d_commitment
                .d_open(&current_vx1, &pk.challenge_r2[i..].to_vec(), net, sid)
                .await?,
        );
        wiring_opens.push(
            pk.d_commitment
                .d_open(&current_num, &pk.challenge_r2[i..].to_vec(), net, sid)
                .await?,
        );

        current_v1x = current_v1x[current_v1x.len() / 2..].to_vec();
        current_vx0 = current_vx0[current_vx0.len() / 2..].to_vec();
        current_vx1 = current_vx1[current_vx1.len() / 2..].to_vec();
        current_eq = current_eq[current_eq.len() / 2..].to_vec();
        current_den = current_den[current_den.len() / 2..].to_vec();
        current_num = current_num[current_num.len() / 2..].to_vec();
        current_h = current_h[current_h.len() / 2..].to_vec();
    }

    if let Some(leader_tree) = top {
        // Get top value of den,h,num
        let eq = random_evaluations(leader_tree.len() / 2);
        let den = random_evaluations(leader_tree.len() / 2);
        let num = random_evaluations(leader_tree.len() / 2);
        // h = num/den
        let h = num.iter().zip(den.iter()).map(|(a, b)| *a / *b).collect();
        // Compute corresponding v1x, vx0, vx1
        let v1x: Vec<_> = leader_tree
            .iter()
            .skip(leader_tree.len() / 2)
            .map(<E as Pairing>::ScalarField::clone)
            .collect();
        let vx0: Vec<_> = leader_tree
            .iter()
            .step_by(2)
            .map(<E as Pairing>::ScalarField::clone)
            .collect();
        let vx1: Vec<_> = leader_tree
            .iter()
            .skip(1)
            .step_by(2)
            .map(<E as Pairing>::ScalarField::clone)
            .collect();
        wiring_commits.push(pk.d_commitment.commit(&h));
        wiring_opens.push(pk.d_commitment.open(&h, &pk.challenge_r2[..s]));
        wiring_commits.push(pk.d_commitment.commit(&num));
        wiring_opens.push(pk.d_commitment.open(&num, &pk.challenge_r2[..s]));
        wiring_commits.push(pk.d_commitment.commit(&vx0));
        wiring_opens.push(pk.d_commitment.open(&vx0, &pk.challenge_r2[..s]));
        wiring_commits.push(pk.d_commitment.commit(&vx1));
        wiring_opens.push(pk.d_commitment.open(&vx1, &pk.challenge_r2[..s]));
        wiring_commits.push(pk.d_commitment.commit(&v1x));
        wiring_opens.push(pk.d_commitment.open(&v1x, &pk.challenge_r2[..s]));
        // Sumcheck for F(x)=eq(x)*(v1x-vx0*vx1).
        wiring_proofs.push(sumcheck_product(&eq, &v1x, &pk.challenge_r2[..s].to_vec()));
        wiring_proofs.push(sumcheck_product(&eq, &vx0, &pk.challenge_r2[..s].to_vec()));
        wiring_proofs.push(sumcheck_product(&vx0, &vx1, &pk.challenge_r2[..s].to_vec()));
        wiring_proofs.push(sumcheck_product(&eq, &den, &pk.challenge_r2[..s].to_vec()));
        wiring_proofs.push(sumcheck_product(&eq, &num, &pk.challenge_r2[..s].to_vec()));
        wiring_proofs.push(sumcheck_product(&h, &den, &pk.challenge_r2[..s].to_vec()));
    }

    end_timer!(wire_timer);
    // end of step 2
    // Open
    let open_timer = start_timer!("Open", net.is_leader());
    gate_identity_commitments.push((
        com_a,
        pk.c_commitment
            .c_open(&pk.a_evals, &pk.challenge, pp, net, sid)
            .await?,
    ));
    gate_identity_commitments.push((
        com_b,
        pk.c_commitment
            .c_open(&pk.b_evals, &pk.challenge, pp, net, sid)
            .await?,
    ));
    gate_identity_commitments.push((
        com_c,
        pk.c_commitment
            .c_open(&pk.c_evals, &pk.challenge, pp, net, sid)
            .await?,
    ));
    gate_identity_commitments.push((
        com_I,
        pk.c_commitment
            .c_open(&pk.I, &pk.challenge, pp, net, sid)
            .await?,
    ));
    gate_identity_commitments.push((
        com_S1,
        pk.c_commitment
            .c_open(&pk.S1, &pk.challenge, pp, net, sid)
            .await?,
    ));
    gate_identity_commitments.push((
        com_S2,
        pk.c_commitment
            .c_open(&pk.S2, &pk.challenge, pp, net, sid)
            .await?,
    ));
    end_timer!(open_timer);

    // let degree_reduce_timer = start_timer!("Degree reduce", net.is_leader());
    // degree_reduce_many(&pk.reduce_target, pp, net, sid).await?;
    // end_timer!(degree_reduce_timer);
    end_timer!(prover_timer);

    end_timer!(timer_all);

    if net.is_leader() {
        println!("Comm: {:?}", net.get_comm());
    }

    Ok((
        (gate_identity_proofs, gate_identity_commitments),
        (wiring_proofs, wiring_commits, wiring_opens),
    ))
}

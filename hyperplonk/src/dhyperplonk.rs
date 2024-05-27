use ark_ec::pairing::Pairing;
use ark_ff::fields::Field;
use ark_std::UniformRand;
use dist_primitive::degree_reduce::degree_reduce_many;
use dist_primitive::random_evaluations;
use dist_primitive::{
    dacc_product::d_acc_product_and_share,
    dpoly_comm::{PolynomialCommitment, PolynomialCommitmentCub},
    dsumcheck::d_sumcheck_product,
    mle::fix_variable,
    utils::serializing_net::MPCSerializeNet,
};
use mpc_net::{end_timer, start_timer};
use mpc_net::{MPCNetError, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;

#[derive(Clone, Debug)]
pub struct PackedProvingParameters<E: Pairing> {
    pub a_evals: Vec<E::ScalarField>,
    pub b_evals: Vec<E::ScalarField>,
    pub c_evals: Vec<E::ScalarField>,
    pub input: Vec<E::ScalarField>,
    pub q1: Vec<E::ScalarField>,
    pub q2: Vec<E::ScalarField>,
    pub sigma_a: Vec<E::ScalarField>,
    pub sigma_b: Vec<E::ScalarField>,
    pub sigma_c: Vec<E::ScalarField>,
    pub sid: Vec<E::ScalarField>,
    // Challenges
    pub eq: Vec<E::ScalarField>,
    pub challenge: Vec<E::ScalarField>,
    pub beta: E::ScalarField,
    pub gamma: E::ScalarField,
    pub commitment: PolynomialCommitment<E>,
    // Masks needed
    pub mask: Vec<E::ScalarField>,
    pub unmask0: Vec<E::ScalarField>,
    pub unmask1: Vec<E::ScalarField>,
    pub unmask2: Vec<E::ScalarField>,
    // Dummies
    pub reduce_target: Vec<E::ScalarField>,
}

impl<E: Pairing> PackedProvingParameters<E> {
    pub fn new(n: usize, l: usize, pp: &PackedSharingParams<E::ScalarField>) -> Self {
        use rand::{rngs::StdRng, SeedableRng};
        let rng = &mut StdRng::from_entropy();
        let gate_count = (1 << n) / l;
        // Shares of witness polynomial M
        let m = random_evaluations(gate_count * 4);
        let a_evals = fix_variable(&m, &vec![E::ScalarField::ZERO, E::ScalarField::ZERO]);
        let b_evals = fix_variable(&m, &vec![E::ScalarField::ZERO, E::ScalarField::ONE]);
        let c_evals = fix_variable(&m, &vec![E::ScalarField::ONE, E::ScalarField::ZERO]);
        // Shares of input polynomial I
        let input = random_evaluations(gate_count);
        // Shares of selector polynomial Q_1, Q_2
        let q1 = random_evaluations(gate_count);
        let q2 = random_evaluations(gate_count);
        // Shares of permutation polynomial S_\sigma and identity polynomial S_id
        let ssigma: Vec<<E as Pairing>::ScalarField> = random_evaluations(gate_count * 4);
        let sigma_a = fix_variable(&ssigma, &vec![E::ScalarField::ZERO, E::ScalarField::ZERO]);
        let sigma_b = fix_variable(&ssigma, &vec![E::ScalarField::ZERO, E::ScalarField::ONE]);
        let sigma_c = fix_variable(&ssigma, &vec![E::ScalarField::ONE, E::ScalarField::ZERO]);
        let sid: Vec<<E as Pairing>::ScalarField> = random_evaluations(gate_count);

        // Shares of eq polynomial. For benchmarking purposes, we generate it in advance and use it repeatedly in the protocol.
        let eq = random_evaluations(gate_count);
        // Distributed polynomial commitment. For benchmarking purposes, we reuse the parameters, which should be avoided in practice.
        let commitment: PolynomialCommitment<E> = PolynomialCommitmentCub::new_single(n, pp);
        // Challenge for polynomial commitment opening.
        let challenge = random_evaluations(n);
        // Other challenges.
        let beta = E::ScalarField::rand(rng);
        let gamma = E::ScalarField::rand(rng);
        // Masks.
        let mask = random_evaluations(gate_count);
        let unmask0 = random_evaluations(gate_count);
        let unmask1 = random_evaluations(gate_count);
        let unmask2 = random_evaluations(gate_count);
        // Dummies
        let reduce_target = random_evaluations(gate_count / l);

        PackedProvingParameters {
            a_evals,
            b_evals,
            c_evals,
            input,
            q1,
            q2,
            sigma_a,
            sigma_b,
            sigma_c,
            sid,
            eq,
            challenge,
            beta,
            gamma,
            commitment,
            mask,
            unmask0,
            unmask1,
            unmask2,
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
        Vec<(
            Vec<Vec<(E::ScalarField, E::ScalarField, E::ScalarField)>>,
            Vec<(E::G1, (E::ScalarField, Vec<E::G1>))>,
        )>,
    ),
    MPCNetError,
> {
    let gate_count = (1 << n) / pp.l;
    
    // Now run the protocol.
    let timer_all = start_timer!("Distributed HyperPlonk", net.is_leader());

    // Commit to 4+2+3=9 polynomials
    let commit_timer = start_timer!("Commit", net.is_leader());
    let com_a = pk
        .commitment
        .d_commit(&vec![pk.a_evals.clone()], &pp, &net, sid)
        .await
        .unwrap()[0];
    let com_b = pk
        .commitment
        .d_commit(&vec![pk.b_evals.clone()], &pp, &net, sid)
        .await
        .unwrap()[0];
    let com_c = pk
        .commitment
        .d_commit(&vec![pk.c_evals.clone()], &pp, &net, sid)
        .await
        .unwrap()[0];
    let com_in = pk
        .commitment
        .d_commit(&vec![pk.input.clone()], &pp, &net, sid)
        .await
        .unwrap()[0];

    let com_q1 = pk
        .commitment
        .d_commit(&vec![pk.q1.clone()], &pp, &net, sid)
        .await
        .unwrap()[0];
    let com_q2 = pk
        .commitment
        .d_commit(&vec![pk.q2.clone()], &pp, &net, sid)
        .await
        .unwrap()[0];

    let com_ssigma_a = pk
        .commitment
        .d_commit(&vec![pk.sigma_a.clone()], &pp, &net, sid)
        .await
        .unwrap()[0];
    let com_ssigma_b = pk
        .commitment
        .d_commit(&vec![pk.sigma_b.clone()], &pp, &net, sid)
        .await
        .unwrap()[0];
    let com_ssigma_c = pk
        .commitment
        .d_commit(&vec![pk.sigma_c.clone()], &pp, &net, sid)
        .await
        .unwrap()[0];
    end_timer!(commit_timer);

    let prover_timer = start_timer!("Distributed HyperPlonk Prover", net.is_leader());

    // Gate identity
    let gate_timer = start_timer!("Gate identity", net.is_leader());
    let mut gate_identity_proofs = Vec::new();
    let mut gate_identity_commitments = Vec::new();
    // Sumcheck F(x)=eq(x)*[q_1(x)*(a(x)+b(x))+q_2(x)*a(x)*b(x)-c(x)+I(x)]
    // In original Hyperplonk this is done with a virtual circuit.
    // We use different sumcheck product to simulate it for implementation simplicity. The computation complexity is the same.
    // Part 1
    gate_identity_proofs
        .push(d_sumcheck_product(&pk.eq, &pk.q1, &pk.challenge, pp, net, sid).await?);
    let sum_ab = pk
        .a_evals
        .iter()
        .zip(pk.b_evals.iter())
        .map(|(a, b)| *a + *b)
        .collect();
    gate_identity_proofs
        .push(d_sumcheck_product(&pk.q1, &sum_ab, &pk.challenge, pp, net, sid).await?);
    // Part 2
    gate_identity_proofs
        .push(d_sumcheck_product(&pk.eq, &pk.q2, &pk.challenge, pp, net, sid).await?);
    gate_identity_proofs
        .push(d_sumcheck_product(&pk.a_evals, &pk.b_evals, &pk.challenge, pp, net, sid).await?);
    gate_identity_proofs
        .push(d_sumcheck_product(&pk.q2, &pk.a_evals, &pk.challenge, pp, net, sid).await?);
    // Part 3
    let sum_ci = pk
        .c_evals
        .iter()
        .zip(pk.input.iter())
        .map(|(a, b)| -*a + b)
        .collect();
    gate_identity_proofs
        .push(d_sumcheck_product(&pk.eq, &sum_ci, &pk.challenge, pp, net, sid).await?);
    end_timer!(gate_timer);

    // Wire identity
    let wire_timer = start_timer!("Wire identity", net.is_leader());
    // Compute f, g
    // f(x) = \prod (w_i(x) + \beta*sid_i(x) + \gamma)
    let timer = start_timer!("Local: Something", net.is_leader());
    let num = (0..gate_count)
        .map(|i| {
            (pk.a_evals[i] + pk.beta * pk.sigma_a[i] + pk.gamma)
                * (pk.b_evals[i] + pk.beta * pk.sigma_b[i] + pk.gamma)
                * (pk.c_evals[i] + pk.beta * pk.sigma_c[i] + pk.gamma)
        })
        .collect();
    let den = (0..gate_count)
        .map(|i| {
            (pk.a_evals[i] + pk.beta * pk.sid[i] + pk.gamma)
                * (pk.b_evals[i] + pk.beta * pk.sid[i] + pk.gamma)
                * (pk.c_evals[i] + pk.beta * pk.sid[i] + pk.gamma)
        })
        .collect();
    let fs: Vec<Vec<E::ScalarField>> = vec![num, den];
    end_timer!(timer);

    let mut wire_identity = Vec::new();
    for evaluations in &fs {
        let mut proofs = Vec::new();
        let mut commits = Vec::new();
        // Compute V
        let (vx0, vx1, v1x) = d_acc_product_and_share(
            evaluations,
            &pk.mask,
            &pk.unmask0,
            &pk.unmask1,
            &pk.unmask2,
            pp,
            net,
            sid,
        )
        .await
        .unwrap();
        // Commit
        let com_v0x = pk
            .commitment
            .d_commit(&vec![evaluations.clone()], &pp, &net, sid)
            .await
            .unwrap()[0];
        let com_v1x = pk
            .commitment
            .d_commit(&vec![v1x.clone()], &pp, &net, sid)
            .await
            .unwrap()[0];
        // Open
        commits.push((
            com_v0x,
            pk.commitment
                .d_open(&evaluations, &pk.challenge, pp, net, sid)
                .await?,
        ));
        commits.push((
            com_v1x,
            pk.commitment
                .d_open(&v1x, &pk.challenge, pp, net, sid)
                .await?,
        ));
        // Sumcheck for F(x)=eq(x)*(v1x-vx0*vx1).
        proofs.push(
            d_sumcheck_product(&pk.eq, &v1x, &pk.challenge, pp, net, sid)
                .await
                .unwrap(),
        );
        proofs.push(
            d_sumcheck_product(&pk.eq, &vx0, &pk.challenge, pp, net, sid)
                .await
                .unwrap(),
        );
        proofs.push(
            d_sumcheck_product(&vx0, &vx1, &pk.challenge, pp, net, sid)
                .await
                .unwrap(),
        );
        wire_identity.push((proofs, commits));
    }
    end_timer!(wire_timer);

    // Open
    let open_timer = start_timer!("Open", net.is_leader());
    gate_identity_commitments.push((
        com_a,
        pk.commitment
            .d_open(&pk.a_evals, &pk.challenge, pp, net, sid)
            .await?,
    ));
    gate_identity_commitments.push((
        com_b,
        pk.commitment
            .d_open(&pk.b_evals, &pk.challenge, pp, net, sid)
            .await?,
    ));
    gate_identity_commitments.push((
        com_c,
        pk.commitment
            .d_open(&pk.c_evals, &pk.challenge, pp, net, sid)
            .await?,
    ));
    gate_identity_commitments.push((
        com_in,
        pk.commitment
            .d_open(&pk.input, &pk.challenge, pp, net, sid)
            .await?,
    ));
    gate_identity_commitments.push((
        com_q1,
        pk.commitment
            .d_open(&pk.q1, &pk.challenge, pp, net, sid)
            .await?,
    ));
    gate_identity_commitments.push((
        com_q2,
        pk.commitment
            .d_open(&pk.q2, &pk.challenge, pp, net, sid)
            .await?,
    ));
    gate_identity_commitments.push((
        com_ssigma_a,
        pk.commitment
            .d_open(&pk.sigma_a, &pk.challenge, pp, net, sid)
            .await?,
    ));
    gate_identity_commitments.push((
        com_ssigma_b,
        pk.commitment
            .d_open(&pk.sigma_b, &pk.challenge, pp, net, sid)
            .await?,
    ));
    gate_identity_commitments.push((
        com_ssigma_c,
        pk.commitment
            .d_open(&pk.sigma_c, &pk.challenge, pp, net, sid)
            .await?,
    ));
    end_timer!(open_timer);

    let degree_reduce_timer = start_timer!("Degree reduce", net.is_leader());
    degree_reduce_many(&pk.reduce_target, pp, net, sid).await?;
    end_timer!(degree_reduce_timer);
    end_timer!(prover_timer);

    end_timer!(timer_all);

    if net.is_leader() {
        println!("Comm: {:?}", net.get_comm());
    }

    Ok((
        (gate_identity_proofs, gate_identity_commitments),
        wire_identity,
    ))
}

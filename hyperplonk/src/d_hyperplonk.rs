use ark_ec::{bls12::Bls12, pairing::Pairing};
use ark_ff::fields::Field;
use ark_std::UniformRand;
use dist_primitive::{
    dacc_product::acc_product,
    dpoly_comm::{PolynomialCommitment, PolynomialCommitmentCub},
    dsumcheck::{d_sumcheck_product, sumcheck_product},
    mle::fix_variable,
    utils::serializing_net::MPCSerializeNet,
};
use mpc_net::{MPCNetError, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;

use crate::hyperplonk::random_evaluations;

pub async fn d_hyperplonk<E: Pairing, Net: MPCSerializeNet>(
    gate_count_log2: usize,
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
    let rng = &mut ark_std::test_rng();
    let gate_count = (1 << gate_count_log2) / pp.l;
    let m = random_evaluations(gate_count * 4);
    let m00 = fix_variable(&m, &vec![E::ScalarField::ZERO, E::ScalarField::ZERO]);
    let m01 = fix_variable(&m, &vec![E::ScalarField::ZERO, E::ScalarField::ONE]);
    let m10 = fix_variable(&m, &vec![E::ScalarField::ONE, E::ScalarField::ZERO]);
    let input = random_evaluations(gate_count);
    let s1 = random_evaluations(gate_count);
    let s2 = random_evaluations(gate_count);
    let eq = random_evaluations(gate_count);
    let g1 = E::G1::rand(rng);
    let g2 = E::G2::rand(rng);
    let s: Vec<E::ScalarField> = random_evaluations(gate_count.trailing_zeros() as usize);
    let commitment: PolynomialCommitment<E> = PolynomialCommitmentCub::new(g1, g2, s).mature();
    let challenge = random_evaluations(gate_count_log2);

    let a_evals = random_evaluations(gate_count);
    let b_evals = random_evaluations(gate_count);
    let c_evals = random_evaluations(gate_count);
    let permute_s1 = random_evaluations(gate_count);
    let permute_s2 = random_evaluations(gate_count);
    let permute_s3 = random_evaluations(gate_count);
    let beta = E::ScalarField::rand(rng);
    let gamma = E::ScalarField::rand(rng);
    let omega = E::ScalarField::rand(rng);
    let num = (0..gate_count)
        .map(|i| {
            (a_evals[i] + beta * permute_s1[i] + gamma)
                * (b_evals[i] + beta * permute_s2[i] + gamma)
                * (c_evals[i] + beta * permute_s3[i] + gamma)
        })
        .collect();
    let den = (0..gate_count)
        .map(|i| {
            (a_evals[i] + beta * omega + gamma)
                * (b_evals[i] + beta * omega + gamma)
                * (c_evals[i] + beta * omega + gamma)
        })
        .collect();
    let fs: Vec<Vec<E::ScalarField>> = vec![num, den];

    // Gate identity
    let mut gate_identity_proofs = Vec::new();
    let mut gate_identity_commitments = Vec::new();
    let m00_commit = commitment.d_commit(&vec![m00], pp, net, sid).await?[0];
    let m01_commit = commitment.d_commit(&vec![m01], pp, net, sid).await?[0];
    let m10_commit = commitment.d_commit(&vec![m10], pp, net, sid).await?[0];
    let input_commit = commitment.d_commit(&vec![input], pp, net, sid).await?[0];
    let s1_commit = commitment.d_commit(&vec![s1], pp, net, sid).await?[0];
    let s2_commit = commitment.d_commit(&vec![s2], pp, net, sid).await?[0];
    gate_identity_commitments.push((
        m00_commit,
        commitment.d_open(&m00, &challenge, pp, net, sid).await?,
    ));
    gate_identity_commitments.push((
        m01_commit,
        commitment.d_open(&m01, &challenge, pp, net, sid).await?,
    ));
    gate_identity_commitments.push((
        m10_commit,
        commitment.d_open(&m10, &challenge, pp, net, sid).await?,
    ));
    gate_identity_commitments.push((
        input_commit,
        commitment.d_open(&input, &challenge, pp, net, sid).await?,
    ));
    gate_identity_commitments.push((
        s1_commit,
        commitment.d_open(&s1, &challenge, pp, net, sid).await?,
    ));
    gate_identity_commitments.push((
        s2_commit,
        commitment.d_open(&s2, &challenge, pp, net, sid).await?,
    ));

    gate_identity_proofs.push(d_sumcheck_product(&eq, &s1, &challenge, pp, net, sid).await?);
    let m00p01 = m00.iter().zip(m01.iter()).map(|(a, b)| *a + *b).collect();
    gate_identity_proofs.push(d_sumcheck_product(&s1, &m00p01, &challenge, pp, net, sid).await?);
    gate_identity_proofs.push(d_sumcheck_product(&eq, &s2, &challenge, pp, net, sid).await?);
    gate_identity_proofs.push(d_sumcheck_product(&m00, &m01, &challenge, pp, net, sid).await?);
    gate_identity_proofs.push(d_sumcheck_product(&s2, &m00, &challenge, pp, net, sid).await?);
    let m10pi = m10.iter().zip(input.iter()).map(|(a, b)| -*a + b).collect();
    gate_identity_proofs.push(d_sumcheck_product(&eq, &m10pi, &challenge, pp, net, sid).await?);

    // Wire identity
    let wire_identity = fs
        .iter()
        .map(|evaluations| async {
            let mut proofs = Vec::new();
            let mut commits = Vec::new();
            let f_commit = commitment
                .d_commit(&vec![evaluations.clone()], pp, net, sid)
                .await
                .unwrap()[0];
            let f_open = commitment
                .d_open(evaluations, &challenge, pp, net, sid)
                .await
                .unwrap();
            let (vx0, vx1, v1x) = d_acc_product(evaluations);
            let v_commit_x0 = commitment.d_commit(&vec![vx0], pp, net, sid).await.unwrap()[0];
            let v_commit_x1 = commitment.d_commit(&vec![vx1], pp, net, sid).await.unwrap()[0];
            let v_commit_1x = commitment.d_commit(&vec![v1x], pp, net, sid).await.unwrap()[0];
            let v_open_x0 = commitment
                .d_open(&vx0, &challenge, pp, net, sid)
                .await
                .unwrap();
            let v_open_x1 = commitment
                .d_open(&vx1, &challenge, pp, net, sid)
                .await
                .unwrap();
            let v_open_1x = commitment
                .d_open(&v1x, &challenge, pp, net, sid)
                .await
                .unwrap();
            commits.push((f_commit, f_open));
            commits.push((v_commit_x0, v_open_x0));
            commits.push((v_commit_x1, v_open_x1));
            commits.push((v_commit_1x, v_open_1x));
            proofs.push(
                d_sumcheck_product(&v1x, &eq, &challenge, pp, net, sid)
                    .await
                    .unwrap(),
            );
            proofs.push(
                d_sumcheck_product(&vx0, &vx1, &challenge, pp, net, sid)
                    .await
                    .unwrap(),
            );
            proofs.push(
                d_sumcheck_product(&eq, &vx0, &challenge, pp, net, sid)
                    .await
                    .unwrap(),
            );
            (proofs, commits)
        })
        .collect().await;
    Ok((
        (gate_identity_proofs, gate_identity_commitments),
        wire_identity,
    ))
}

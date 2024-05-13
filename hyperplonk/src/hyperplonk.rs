use ark_ec::{bls12::Bls12, pairing::Pairing};
use ark_ff::fields::Field;
use ark_std::UniformRand;
use dist_primitive::{
    dacc_product::acc_product, dpoly_comm::{PolynomialCommitment, PolynomialCommitmentCub}, dsumcheck::sumcheck_product, mle::fix_variable
};
pub fn polyfill_hyperplonk<E: Pairing>(
    gate_count_log2: usize,
) -> (
    (
        Vec<Vec<(E::ScalarField, E::ScalarField, E::ScalarField)>>,
        Vec<(E::G1, (E::ScalarField, Vec<E::G1>))>,
    ),
    Vec<(
        Vec<Vec<(E::ScalarField, E::ScalarField, E::ScalarField)>>,
        Vec<(E::G1, (E::ScalarField, Vec<E::G1>))>,
    )>,
) {
    // Preparation
    let rng = &mut ark_std::test_rng();
    let gate_count = 1 << gate_count_log2;
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
    let s: Vec<E::ScalarField> = random_evaluations(gate_count_log2);
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
    let fs = vec![num, den];

    // Gate identity
    let mut gate_identity_proofs = Vec::new();
    let mut gate_identity_commitments = Vec::new();
    let m00_commit = commitment.commit(&m00);
    let m01_commit = commitment.commit(&m01);
    let m10_commit = commitment.commit(&m10);
    let input_commit = commitment.commit(&input);
    let s1_commit = commitment.commit(&s1);
    let s2_commit = commitment.commit(&s2);
    gate_identity_commitments.push((m00_commit, commitment.open(&m00, &challenge)));
    gate_identity_commitments.push((m01_commit, commitment.open(&m01, &challenge)));
    gate_identity_commitments.push((m10_commit, commitment.open(&m10, &challenge)));
    gate_identity_commitments.push((input_commit, commitment.open(&input, &challenge)));
    gate_identity_commitments.push((s1_commit, commitment.open(&s1, &challenge)));
    gate_identity_commitments.push((s2_commit, commitment.open(&s2, &challenge)));

    gate_identity_proofs.push(sumcheck_product(&eq, &s1, &challenge));
    let m00p01 = m00.iter().zip(m01.iter()).map(|(a, b)| *a + *b).collect();
    gate_identity_proofs.push(sumcheck_product(&s1, &m00p01, &challenge));
    gate_identity_proofs.push(sumcheck_product(&eq, &s2, &challenge));
    gate_identity_proofs.push(sumcheck_product(&m00, &m01, &challenge));
    gate_identity_proofs.push(sumcheck_product(&s2, &m00, &challenge));
    let m10pi = m10.iter().zip(input.iter()).map(|(a, b)| -*a + b).collect();
    gate_identity_proofs.push(sumcheck_product(&eq, &m10pi, &challenge));

    // Wire identity
    let wire_identity = fs
        .iter()
        .map(|evaluations| {
            let mut proofs = Vec::new();
            let mut commits = Vec::new();
            let f_commit = commitment.commit(evaluations);
            let f_open = commitment.open(evaluations, &challenge);
            let (vx0, vx1, v1x) = acc_product(evaluations);
            let v_commit_x0 = commitment.commit(&vx0);
            let v_commit_x1 = commitment.commit(&vx1);
            let v_commit_1x = commitment.commit(&v1x);
            let v_open_x0 = commitment.open(&vx0, &challenge);
            let v_open_x1 = commitment.open(&vx1, &challenge);
            let v_open_1x = commitment.open(&v1x, &challenge);
            commits.push((f_commit, f_open));
            commits.push((v_commit_x0, v_open_x0));
            commits.push((v_commit_x1, v_open_x1));
            commits.push((v_commit_1x, v_open_1x));
            proofs.push(sumcheck_product(&v1x, &eq, &challenge));
            proofs.push(sumcheck_product(&vx0, &vx1, &challenge));
            proofs.push(sumcheck_product(&eq, &vx0, &challenge));
            (proofs, commits)
        })
        .collect();
    (
        (gate_identity_proofs, gate_identity_commitments),
        wire_identity,
    )
}

fn random_evaluations<F: UniformRand>(n: usize) -> Vec<F> {
    (0..n)
        .map(|_| F::rand(&mut ark_std::test_rng()))
        .collect::<Vec<_>>()
}

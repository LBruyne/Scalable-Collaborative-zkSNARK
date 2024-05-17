use ark_ec::pairing::Pairing;
use ark_ff::FftField;

use ark_std::UniformRand;
use ark_std::One;

use dist_primitive::dpoly_comm::PolynomialCommitmentCub;
use dist_primitive::dsumcheck::sumcheck_product;
use dist_primitive::mle::DenseMultilinearExtension;
use mpc_net::{end_timer, start_timer};
use rand::random;
use std::hint::black_box;

use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct SparseMultilinearExtension<F>(pub HashMap<(F, F, F), F>);

/// A GKR function is in the form of f1(g,x,y)f2(x)f3(y), where g is the challenge point. This is an proof-of-concept implementation of the linear-time algorithm. Only for benchmarking purposes.
/// Refer to Libra's paper for more details.
pub fn local_gkr_function<F: FftField>(
    f1: &SparseMultilinearExtension<F>,
    f2: &DenseMultilinearExtension<F>,
    f3: &DenseMultilinearExtension<F>,
    challenge_g: &Vec<F>,
    challenge_u: &Vec<F>,
    challenge_v: &Vec<F>,
) -> Vec<(F, F, F)> {
    // Initialize phase one.
    let hg = initialize_phase_one(f1, f3, challenge_g);
    // Sumcheck product 1.
    let mut proof1 = sumcheck_product(&hg.evaluations, &f2.evaluations, challenge_u);
    // Initialize phase two.
    let f1 = initialize_phase_two(f1, challenge_g, challenge_v);
    // Compute polynomial. Omitted for simplicity.
    // let f2_u = fix_variable(&f2.evaluations, challenge_u)[0];
    let f2_u = F::one();
    let f3_f2u = f3.mul(&f2_u);
    // Sumcheck product 2.
    let proof2 = sumcheck_product(&f1.evaluations, &f3_f2u.evaluations, challenge_v);
    proof1.extend(proof2);
    proof1
}

pub fn initialize_phase_one<F: FftField>(
    f1: &SparseMultilinearExtension<F>,
    f3: &DenseMultilinearExtension<F>,
    challenge_g: &Vec<F>,
) -> DenseMultilinearExtension<F> {
    black_box(f1);
    black_box(f3);
    black_box(challenge_g);
    phase_initilization(f1)
}

pub fn initialize_phase_two<F: FftField>(
    f1: &SparseMultilinearExtension<F>,
    challenge_g: &Vec<F>,
    challenge_v: &Vec<F>,
) -> DenseMultilinearExtension<F> {
    black_box(f1);
    black_box(challenge_g);
    black_box(challenge_v);
    phase_initilization(f1)
}

/// This is a simplified version to simulate the complexity.
pub fn phase_initilization<F: FftField>(
    f1: &SparseMultilinearExtension<F>,
) -> DenseMultilinearExtension<F> {
    let mut evaluations = vec![F::zero(); f1.0.len()];
    let _simulation = {
        for (_k, v) in &f1.0 {
            evaluations[random::<usize>() % f1.0.len()] += *v * *v;
        }
    };
    let res = DenseMultilinearExtension::from_evaluations_slice(f1.0.len(), &evaluations);
    res
}

/// A simplified local GKR without any optimization only for benchmarking purposes.
pub fn local_gkr<E: Pairing>(
    depth: usize,
    width: usize,
) -> (
    Vec<Vec<Vec<(E::ScalarField, E::ScalarField, E::ScalarField)>>>,
    E::G1,
    (E::ScalarField, Vec<E::G1>),
) {
    let mut proof = Vec::new();
    use rand::{rngs::StdRng, SeedableRng};

    let rng = &mut StdRng::from_entropy();
    // A polynomial representing mult and add.
    let mut f1 = SparseMultilinearExtension::<E::ScalarField>(HashMap::new());
    for _ in 0..(1 << width) {
        f1.0.insert(
            (
                E::ScalarField::rand(rng),
                E::ScalarField::rand(rng),
                E::ScalarField::rand(rng),
            ),
            E::ScalarField::one(),
        );
    }
    let f1s = vec![f1; depth];
    // A polynomial representing V.
    let poly_v = DenseMultilinearExtension::from_evaluations_slice(
        0,
        &(0..(1 << width))
            .map(|_| E::ScalarField::rand(rng))
            .collect::<Vec<_>>(),
    );
    let poly_vs = vec![poly_v; depth];
    // Challenge g, u, v, r. For benchmarking purposes, we generate them in advance and use them repeatedly in the protocol.
    let challenge_g: Vec<E::ScalarField> = (0..width)
        .map(|_| E::ScalarField::rand(rng))
        .collect::<Vec<_>>();
    let challenge_u: Vec<E::ScalarField> = (0..width)
        .map(|_| E::ScalarField::rand(rng))
        .collect::<Vec<_>>();
    let challenge_v: Vec<E::ScalarField> = (0..width)
        .map(|_| E::ScalarField::rand(rng))
        .collect::<Vec<_>>();
    let challenge_r: Vec<E::ScalarField> = (0..width)
    .map(|_| E::ScalarField::rand(rng))
    .collect::<Vec<_>>();
    // Polynomial commitment.
    let g1 = E::G1::rand(rng);
    let g2 = E::G2::rand(rng);
    let s = (0..width as usize)
        .map(|_| E::ScalarField::rand(rng))
        .collect::<Vec<_>>();
    let commitment = PolynomialCommitmentCub::<E>::new_toy(g1, g2, s).mature();

    // Now run the protocol.
    let timer_all = start_timer!("Local GKR");

    // Commit to V_d
    let commit_timer = start_timer!("Commit");
    let commit = commitment.commit(&poly_vs[0].evaluations);
    end_timer!(commit_timer);

    let prover_timer = start_timer!("GKR Prover");

    // GKR prover
    let gkr_timer = start_timer!("GKR Round");
    for _ in 0..depth {
        let mut layer_proof = Vec::new();
        // For GKR relation,
        // in each round we actually need to run 3 GKR functions.
        // 1 with the form mult(g,x,y)V(x)V(y)
        // 2 with the form add(g,x,y)V(x) and add(g,x,y)V(y)
        // To mimic, at last we run 3 GKR functions in each layer.
        for _ in 0..3 {
            layer_proof.push(local_gkr_function(
                black_box(&f1s[0]),
                black_box(&poly_vs[0]),
                black_box(&poly_vs.clone()[0]),
                black_box(&challenge_g.clone()),
                black_box(&challenge_u.clone()),
                black_box(&challenge_v.clone()),
            ));
        }
        proof.push(layer_proof);
    }
    end_timer!(gkr_timer);

    // Open V_d at a random challenge point.
    let timer_open = start_timer!("Open");
    let (value, com_proof) = commitment.open(&poly_vs[depth-1].evaluations, &challenge_r);
    end_timer!(timer_open);

    end_timer!(prover_timer);

    end_timer!(timer_all);

    (proof, commit, (value, com_proof))
}

use ark_ec::pairing::Pairing;
use ark_ff::fields::Field;
use ark_std::UniformRand;
use dist_primitive::{
    dacc_product::acc_product,
    dpoly_comm::{PolynomialCommitment, PolynomialCommitmentCub},
    dsumcheck::sumcheck_product,
    mle::fix_variable,
};

use dist_primitive::random_evaluations;
use mpc_net::{end_timer, start_timer};

/// This is a simplified version without any optimization to simulate the complexity.
pub fn local_hyperplonk<E: Pairing>(
    n: usize, // n is the log2 of the circuit size
) -> ((Vec<Vec<(<E as Pairing>::ScalarField, <E as Pairing>::ScalarField, <E as Pairing>::ScalarField)>>, Vec<(<E as Pairing>::G1, (<E as Pairing>::ScalarField, Vec<<E as Pairing>::G1>))>), (Vec<Vec<(<E as Pairing>::ScalarField, <E as Pairing>::ScalarField, <E as Pairing>::ScalarField)>>, Vec<<E as Pairing>::G1>, Vec<(<E as Pairing>::ScalarField, Vec<<E as Pairing>::G1>)>)) {
    use rand::{rngs::StdRng, SeedableRng};
    let rng = &mut StdRng::from_entropy();
    let gate_count = 1 << n;
    // Witness polynomial M (with n+2 variables)
    let m = random_evaluations(gate_count * 4);
    let a_evals = fix_variable(&m, &vec![E::ScalarField::ZERO, E::ScalarField::ZERO]);
    let b_evals = fix_variable(&m, &vec![E::ScalarField::ZERO, E::ScalarField::ONE]);
    let c_evals = fix_variable(&m, &vec![E::ScalarField::ONE, E::ScalarField::ZERO]);
    // Input polynomial I
    let input = random_evaluations(gate_count);
    // Selector polynomial Q_1, Q_2
    let q1 = random_evaluations(gate_count);
    let q2 = random_evaluations(gate_count);
    // Permutation polynomial S_\sigma and identity polynomial S_id
    let ssigma:Vec<E::ScalarField> = random_evaluations(gate_count * 4);

    // Eq polynomial. For benchmarking purposes, we generate it in advance and use it repeatedly in the protocol.
    let eq = random_evaluations(gate_count);
    let eq_p2 = random_evaluations(gate_count*4);
    // Polynomial commitment. For benchmarking purposes, we reuse the parameters, which should be avoided in practice.
    let g1 = E::G1::rand(rng);
    let g2 = E::G2::rand(rng);
    let s: Vec<E::ScalarField> = random_evaluations(n+2);
    let commitment: PolynomialCommitment<E> = PolynomialCommitmentCub::new_toy(g1, g2, s).mature();
    // Challenge for polynomial commitment opening.
    let challenge = random_evaluations(n);
    let challengep2 = random_evaluations(n+2);
    let sid: Vec<E::ScalarField> = random_evaluations(gate_count*4);
    let beta = E::ScalarField::rand(rng);
    let alpha = E::ScalarField::rand(rng);

    // Now run the protocol.
    let timer_all = start_timer!("Local HyperPlonk");

    // Commit to 4+2=6 polynomials
    let commit_timer = start_timer!("Commit");
    let com_a = commitment.commit(&a_evals);
    let com_b = commitment.commit(&b_evals);
    let com_c = commitment.commit(&c_evals);
    let com_in = commitment.commit(&input);

    let com_q1 = commitment.commit(&q1);
    let com_q2 = commitment.commit(&q2);

    end_timer!(commit_timer);

    let prover_timer = start_timer!("HyperPlonk Prover");

    // Gate identity
    let gate_timer = start_timer!("Gate identity");
    let mut gate_identity_proofs = Vec::new();
    let mut gate_identity_commitments = Vec::new();
    // Sumcheck F(x)=eq(x)*[q_1(x)*(a(x)+b(x))+q_2(x)*a(x)*b(x)-c(x)+I(x)]
    // In original Hyperplonk this is done with a virtual circuit.
    // We use different sumcheck product to simulate it for implementation simplicity. The computation complexity is the same.
    // Part 1
    gate_identity_proofs.push(sumcheck_product(&eq, &q1, &challenge));
    let sum_ab = a_evals
        .iter()
        .zip(b_evals.iter())
        .map(|(a, b)| *a + *b)
        .collect();
    gate_identity_proofs.push(sumcheck_product(&q1, &sum_ab, &challenge));
    // Part 2
    gate_identity_proofs.push(sumcheck_product(&eq, &q2, &challenge));
    gate_identity_proofs.push(sumcheck_product(&a_evals, &b_evals, &challenge));
    gate_identity_proofs.push(sumcheck_product(&q2, &a_evals, &challenge));
    // Part 3
    let sum_ci = c_evals
        .iter()
        .zip(input.iter())
        .map(|(a, b)| -*a + *b)
        .collect();
    gate_identity_proofs.push(sumcheck_product(&eq, &sum_ci, &challenge));
    end_timer!(gate_timer);

    // Wire identity
    let mut wiring_proofs = Vec::new();
    let mut wiring_commits = Vec::new();
    let mut wiring_opens = Vec::new();
    let wire_timer = start_timer!("Wire identity");
    // Compute f, g
    // f(x) = \prod (w_i(x) + \alpha*sid_i(x) + \beta)
    // g(x) = \prod (w_i(x) + \alpha*ssigma_i(x) + \beta)
    let num: Vec<_> = (0..gate_count*4)
        .map(|i| {
            m[i] + alpha * sid[i] + beta
        })
        .collect();
    let den: Vec<_> = (0..gate_count*4)
        .map(|i| {
            m[i] + alpha * ssigma[i] + beta
        })
        .collect();
    let h = num.iter().zip(den.iter()).map(|(a, b)| *a / *b).collect();
    // Compute V, where v0x = h
    let (vx0, vx1, v1x) = acc_product(&h);
    // Commit
    // Open (Here we omit repeated openings on the same polynomial).
    wiring_commits.push(commitment.commit(&sid));
    wiring_opens.push(commitment.open(&sid, &challengep2));
    wiring_commits.push(commitment.commit(&ssigma));
    wiring_opens.push(commitment.open(&ssigma, &challengep2));
    wiring_commits.push(commitment.commit(&h));
    wiring_opens.push(commitment.open(&h, &challengep2));
    wiring_commits.push(commitment.commit(&num));
    wiring_opens.push(commitment.open(&num, &challengep2));
    wiring_commits.push(commitment.commit(&den));
    wiring_opens.push(commitment.open(&den, &challengep2));
    wiring_commits.push(commitment.commit(&vx0));
    wiring_opens.push(commitment.open(&vx0, &challengep2));
    wiring_commits.push(commitment.commit(&vx1));
    wiring_opens.push(commitment.open(&vx1, &challengep2));
    wiring_commits.push(commitment.commit(&v1x));
    wiring_opens.push(commitment.open(&v1x, &challengep2));
    // Sumcheck for F(x)=eq(x)*(v1x-vx0*vx1).
    wiring_proofs.push(sumcheck_product(&eq_p2, &v1x, &challengep2));
    wiring_proofs.push(sumcheck_product(&eq_p2, &vx0, &challengep2));
    wiring_proofs.push(sumcheck_product(&vx0, &vx1, &challengep2));
    // Sumcheck for F(x)=eq(x)*(g*v0x-f).
    wiring_proofs.push(sumcheck_product(&eq_p2, &den, &challengep2));
    wiring_proofs.push(sumcheck_product(&h, &den, &challengep2));
    wiring_proofs.push(sumcheck_product(&eq_p2, &num, &challengep2));
    end_timer!(wire_timer);

    // Open
    let open_timer = start_timer!("Open");
    gate_identity_commitments.push((com_a, commitment.open(&a_evals, &challenge)));
    gate_identity_commitments.push((com_b, commitment.open(&b_evals, &challenge)));
    gate_identity_commitments.push((com_c, commitment.open(&c_evals, &challenge)));
    gate_identity_commitments.push((com_in, commitment.open(&input, &challenge)));
    gate_identity_commitments.push((com_q1, commitment.open(&q1, &challenge)));
    gate_identity_commitments.push((com_q2, commitment.open(&q2, &challenge)));
    end_timer!(open_timer);

    end_timer!(prover_timer);

    end_timer!(timer_all);
    (
        (gate_identity_proofs, gate_identity_commitments),
        (wiring_proofs, wiring_commits, wiring_opens),
    )
}

pub fn local_hyperplonkpp<E: Pairing>(
    n: usize, // n is the log2 of the circuit size
) -> ((Vec<Vec<(<E as Pairing>::ScalarField, <E as Pairing>::ScalarField, <E as Pairing>::ScalarField)>>, Vec<(<E as Pairing>::G1, (<E as Pairing>::ScalarField, Vec<<E as Pairing>::G1>))>), (Vec<Vec<(<E as Pairing>::ScalarField, <E as Pairing>::ScalarField, <E as Pairing>::ScalarField)>>, Vec<<E as Pairing>::G1>, Vec<(<E as Pairing>::ScalarField, Vec<<E as Pairing>::G1>)>)) {
    use rand::{rngs::StdRng, SeedableRng};
    let rng = &mut StdRng::from_entropy();
    let gate_count = 1 << n;
    // Witness polynomial M (with n+2 variables)
    let m = random_evaluations(gate_count * 4);
    let a_evals = fix_variable(&m, &vec![E::ScalarField::ZERO, E::ScalarField::ZERO]);
    let b_evals = fix_variable(&m, &vec![E::ScalarField::ZERO, E::ScalarField::ONE]);
    let c_evals = fix_variable(&m, &vec![E::ScalarField::ONE, E::ScalarField::ZERO]);
    // Input polynomial I
    let input = random_evaluations(gate_count);
    // Selector polynomial Q_1, Q_2
    let q1 = random_evaluations(gate_count);
    let q2 = random_evaluations(gate_count);
    // Permutation polynomial S_\sigma and identity polynomial S_id
    let ssigma:Vec<E::ScalarField> = random_evaluations(gate_count * 4);

    // Eq polynomial. For benchmarking purposes, we generate it in advance and use it repeatedly in the protocol.
    let eq = random_evaluations(gate_count);
    let eq_p2 = random_evaluations(gate_count*4);
    // Polynomial commitment. For benchmarking purposes, we reuse the parameters, which should be avoided in practice.
    let g1 = E::G1::rand(rng);
    let g2 = E::G2::rand(rng);
    let s: Vec<E::ScalarField> = random_evaluations(n+2);
    let commitment: PolynomialCommitment<E> = PolynomialCommitmentCub::new_toy(g1, g2, s).mature();
    // Challenge for polynomial commitment opening.
    let challenge = random_evaluations(n);
    let challengep2 = random_evaluations(n+2);
    let challengep2_2 = random_evaluations(n+2);
    let sid: Vec<E::ScalarField> = random_evaluations(gate_count*4);
    let beta = E::ScalarField::rand(rng);
    let alpha = E::ScalarField::rand(rng);

    // Now run the protocol.
    let timer_all = start_timer!("Local HyperPlonk++");

    // Commit to 4+2=6 polynomials
    let commit_timer = start_timer!("Commit");
    let com_a = commitment.commit(&a_evals);
    let com_b = commitment.commit(&b_evals);
    let com_c = commitment.commit(&c_evals);
    let com_in = commitment.commit(&input);

    let com_q1 = commitment.commit(&q1);
    let com_q2 = commitment.commit(&q2);

    end_timer!(commit_timer);

    let prover_timer = start_timer!("HyperPlonk Prover");

    // Gate identity
    let gate_timer = start_timer!("Gate identity");
    let mut gate_identity_proofs = Vec::new();
    let mut gate_identity_commitments = Vec::new();
    // Sumcheck F(x)=eq(x)*[q_1(x)*(a(x)+b(x))+q_2(x)*a(x)*b(x)-c(x)+I(x)]
    // In original Hyperplonk this is done with a virtual circuit.
    // We use different sumcheck product to simulate it for implementation simplicity. The computation complexity is the same.
    // Part 1
    gate_identity_proofs.push(sumcheck_product(&eq, &q1, &challenge));
    let sum_ab = a_evals
        .iter()
        .zip(b_evals.iter())
        .map(|(a, b)| *a + *b)
        .collect();
    gate_identity_proofs.push(sumcheck_product(&q1, &sum_ab, &challenge));
    // Part 2
    gate_identity_proofs.push(sumcheck_product(&eq, &q2, &challenge));
    gate_identity_proofs.push(sumcheck_product(&a_evals, &b_evals, &challenge));
    gate_identity_proofs.push(sumcheck_product(&q2, &a_evals, &challenge));
    // Part 3
    let sum_ci = c_evals
        .iter()
        .zip(input.iter())
        .map(|(a, b)| -*a + *b)
        .collect();
    gate_identity_proofs.push(sumcheck_product(&eq, &sum_ci, &challenge));
    end_timer!(gate_timer);

    // Wire identity
    let mut wiring_proofs = Vec::new();
    let mut wiring_commits = Vec::new();
    let mut wiring_opens = Vec::new();
    let wire_timer = start_timer!("Wire identity");
    // s is M' in the paper.
    let s = random_evaluations(gate_count * 4);
    wiring_commits.push(commitment.commit(&s));
    // Sumcheck for V(r_1) = \sumcheck M' * V
    wiring_proofs.push(sumcheck_product(&m, &s, &challengep2));
    wiring_opens.push(commitment.open(&s, &challengep2));
    wiring_opens.push(commitment.open(&m, &challengep2));
    wiring_opens.push(commitment.open(&m, &challengep2_2));
    // Compute f, g
    // f(x) = \prod (M'(x) + \alpha*sid(x) + \beta)
    let num: Vec<_> = (0..gate_count*4)
        .map(|i| {
            s[i] + alpha * sid[i] + beta
        })
        .collect();
    // g(x) = \prod (eq(x) + \alpha*ssigma(x) + \beta)
    let den: Vec<_> = (0..gate_count*4)
        .map(|i| {
            eq_p2[i] + alpha * ssigma[i] + beta
        })
        .collect();
    let h = num.iter().zip(den.iter()).map(|(a, b)| *a / *b).collect();
    // Compute V
    let (vx0, vx1, v1x) = acc_product(&h);
    // Commit
    // Open (Here we omit repeated openings on the same polynomial).
    wiring_commits.push(commitment.commit(&sid));
    wiring_opens.push(commitment.open(&sid, &challengep2));
    wiring_commits.push(commitment.commit(&ssigma));
    wiring_opens.push(commitment.open(&ssigma, &challengep2));
    wiring_commits.push(commitment.commit(&h));
    wiring_opens.push(commitment.open(&h, &challengep2));
    wiring_commits.push(commitment.commit(&num));
    wiring_opens.push(commitment.open(&num, &challengep2));
    wiring_commits.push(commitment.commit(&den));
    wiring_opens.push(commitment.open(&den, &challengep2));
    wiring_commits.push(commitment.commit(&vx0));
    wiring_opens.push(commitment.open(&vx0, &challengep2));
    wiring_commits.push(commitment.commit(&vx1));
    wiring_opens.push(commitment.open(&vx1, &challengep2));
    wiring_commits.push(commitment.commit(&v1x));
    wiring_opens.push(commitment.open(&v1x, &challengep2));
    // Sumcheck for F(x)=eq(x)*(v1x-vx0*vx1).
    wiring_proofs.push(sumcheck_product(&eq_p2, &v1x, &challengep2));
    wiring_proofs.push(sumcheck_product(&eq_p2, &vx0, &challengep2));
    wiring_proofs.push(sumcheck_product(&vx0, &vx1, &challengep2));
    // Sumcheck for F(x)=eq(x)*(g*v0x-f).
    wiring_proofs.push(sumcheck_product(&eq_p2, &den, &challengep2));
    wiring_proofs.push(sumcheck_product(&h, &den, &challengep2));
    wiring_proofs.push(sumcheck_product(&eq_p2, &num, &challengep2));
    end_timer!(wire_timer);

    // Open
    let open_timer = start_timer!("Open");
    gate_identity_commitments.push((com_a, commitment.open(&a_evals, &challenge)));
    gate_identity_commitments.push((com_b, commitment.open(&b_evals, &challenge)));
    gate_identity_commitments.push((com_c, commitment.open(&c_evals, &challenge)));
    gate_identity_commitments.push((com_in, commitment.open(&input, &challenge)));
    gate_identity_commitments.push((com_q1, commitment.open(&q1, &challenge)));
    gate_identity_commitments.push((com_q2, commitment.open(&q2, &challenge)));
    end_timer!(open_timer);

    end_timer!(prover_timer);

    end_timer!(timer_all);
    (
        (gate_identity_proofs, gate_identity_commitments),
        (wiring_proofs, wiring_commits, wiring_opens),
    )
}

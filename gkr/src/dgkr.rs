use std::hint::black_box;

use ark_ec::pairing::Pairing;
use ark_ff::FftField;

use dist_primitive::{degree_reduce::degree_reduce, dpoly_comm::PolynomialCommitment, dsumcheck::d_sumcheck_product, end_timer, mle::{d_fix_variable, PackedDenseMultilinearExtension}, start_timer, unpack::d_unpack_0, utils::serializing_net::MPCSerializeNet};
use mpc_net::{MPCNetError, MultiplexedStreamID};
use rand::random;
use secret_sharing::pss::PackedSharingParams;

use crate::gkr::SparseMultilinearExtension;

/// This is a proof-of-concept implementation of the distributed GKR function.
pub async fn d_gkr_function<F: FftField, Net: MPCSerializeNet>(
    shares_f1: &SparseMultilinearExtension<F>,
    shares_f2: &PackedDenseMultilinearExtension<F>,
    shares_f3: &PackedDenseMultilinearExtension<F>,
    challenge_g: &Vec<F>,
    challenge_u: &Vec<F>,
    challenge_v: &Vec<F>,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<Vec<(F, F, F)>, MPCNetError> {
    let timer_initialize_phase_one = start_timer!("Distributed initialize phase one");
    let hg = d_initialize_phase_one(shares_f1, shares_f3, challenge_g, pp, net, sid).await?;
    end_timer!(timer_initialize_phase_one);
    let timer_sumcheck_product = start_timer!("Distributed sumcheck product 1");
    let mut proof1 =
        d_sumcheck_product(&hg.shares, &shares_f2.shares, challenge_u, pp, net, sid).await?;
    end_timer!(timer_sumcheck_product);
    let timer_initialize_phase_two = start_timer!("Distributed initialize phase two");
    let f1 = d_initialize_phase_two(shares_f1, challenge_g, challenge_v, pp, net, sid).await?;
    end_timer!(timer_initialize_phase_two);
    let timer_f3_f2u = start_timer!("Calculate f3*f2(u)");
    let f2_u = d_fix_variable(&shares_f2.shares, challenge_u, pp, net, sid).await?[0];
    let f2_u = d_unpack_0(f2_u, pp, net, sid).await?;
    let shares_f3_f2u = shares_f3.mul(&f2_u);
    end_timer!(timer_f3_f2u);
    let timer_sumcheck_product = start_timer!("Distributed sumcheck product 2");
    let proof2 =
        d_sumcheck_product(&f1.shares, &shares_f3_f2u.shares, challenge_v, pp, net, sid).await?;
    end_timer!(timer_sumcheck_product);
    proof1.extend(proof2);
    Ok(proof1)
}

pub async fn d_initialize_phase_one<F: FftField, Net: MPCSerializeNet>(
    shares_f1: &SparseMultilinearExtension<F>,
    shares_f3: &PackedDenseMultilinearExtension<F>,
    challenge_g: &Vec<F>,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<PackedDenseMultilinearExtension<F>, MPCNetError> {
    black_box(shares_f1);
    black_box(shares_f3);
    black_box(challenge_g);
    Ok(PackedDenseMultilinearExtension::from_evaluations_slice(
        challenge_g.len(),
        &d_phase_initilization(shares_f1, pp, net, sid).await?,
    ))
}

pub async fn d_initialize_phase_two<F: FftField, Net: MPCSerializeNet>(
    shares_f1: &SparseMultilinearExtension<F>,
    challenge_g: &Vec<F>,
    challenge_v: &Vec<F>,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<PackedDenseMultilinearExtension<F>, MPCNetError> {
    // Now this comes from Father Christmas
    black_box(shares_f1);
    black_box(challenge_g);
    black_box(challenge_v);
    Ok(PackedDenseMultilinearExtension::from_evaluations_slice(
        challenge_g.len(),
        &d_phase_initilization(shares_f1, pp, net, sid).await?,
    ))
}

pub async fn d_phase_initilization<F: FftField, Net: MPCSerializeNet>(
    shares_f1: &SparseMultilinearExtension<F>,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<Vec<F>, MPCNetError> {
    // Handle each point in f1
    // Besides, only 1/N computations should be done on party 0
    let mut evaluations = vec![F::zero(); shares_f1.0.len()];
    let _simulation = {
        for (_k, v) in &shares_f1.0 {
            evaluations[random::<usize>() % shares_f1.0.len()] += degree_reduce(*v * *v, pp, net, sid).await?;
        }
    };
    Ok(evaluations)
}

/// A proof-of-concept implementation of distributed GKR proof.
/// Assume the party has required pre-processings.
pub async fn d_gkr<E: Pairing, Net: MPCSerializeNet>(
    depth: usize,
    width: usize,
    f1s_shares: &Vec<SparseMultilinearExtension<E::ScalarField>>,
    poly_vs_shares: &Vec<PackedDenseMultilinearExtension<E::ScalarField>>,
    challenge_g: &Vec<E::ScalarField>,
    challenge_u: &Vec<E::ScalarField>,
    challenge_v: &Vec<E::ScalarField>,
    challenge_r: &Vec<E::ScalarField>,
    mature: &PolynomialCommitment<E>,
    pp: &PackedSharingParams<E::ScalarField>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<
    (
        Vec<Vec<Vec<(E::ScalarField, E::ScalarField, E::ScalarField)>>>,
        E::G1,
        (E::ScalarField, Vec<E::G1>),
    ),
    MPCNetError,
> {
    let _ = width;
    let mut proof = Vec::new();

    let timer_all: dist_primitive::utils::timer::TimerInfo = start_timer!("Distributed GKR", net.is_leader());

    // Commit
    let commit_timer = start_timer!("dCommit", net.is_leader());
    let commit = mature.d_commit(&vec![poly_vs_shares[0].shares.clone()], pp, net, sid).await?;
    end_timer!(commit_timer);

    let timer_gkr_rounds = start_timer!("dGKR rounds", net.is_leader());
    for _ in 0..depth {
        let mut layer_proof = Vec::new();
        // For GKR relation,
        // in each round we actually need to run 3 GKR functions.
        // 1 with the form mult(g,x,y)V(x)V(y)
        // 2 with the form add(g,x,y)V(x) and add(g,x,y)V(y)
        // To mimic, at last we run 3 GKR functions in each layer.
        for _ in 0..3 {
            layer_proof.push(
                d_gkr_function(
                    black_box(&f1s_shares[0]),
                    black_box(&poly_vs_shares[0]),
                    black_box(&poly_vs_shares.clone()[0]),
                    black_box(&challenge_g.clone()),
                    black_box(&challenge_u.clone()),
                    black_box(&challenge_v.clone()),
                    pp,
                    net,
                    sid,
                )
                .await?,
            );
        }
        proof.push(layer_proof);
    }
    end_timer!(timer_gkr_rounds);

    // Open
    let open_timer = start_timer!("dOpen", net.is_leader());
    let open = mature.d_open(&poly_vs_shares[0].shares, &challenge_r, pp, net, sid).await?;
    end_timer!(open_timer);

    end_timer!(timer_all);

    if net.is_leader() {
        println!("Comm: {:?}", net.get_comm());
    }

    Ok((proof, commit[0], open))
}

use ark_ec::pairing::Pairing;
use ark_ff::FftField;

use ark_std::perf_trace::AtomicUsize;

use ark_std::UniformRand;
use ark_std::Zero;
use dist_primitive::degree_reduce::degree_reduce;

use dist_primitive::dpoly_comm::PolynomialCommitment;
use dist_primitive::dpoly_comm::PolynomialCommitmentCub;
use dist_primitive::dsumcheck::d_sumcheck_product;
use dist_primitive::dsumcheck::sumcheck_product;
use dist_primitive::end_timer;
use dist_primitive::mle::d_fix_variable;
use dist_primitive::mle::fix_variable;
use dist_primitive::mle::DenseMultilinearExtension;
use dist_primitive::start_timer;
use dist_primitive::timed;
use dist_primitive::unpack::d_unpack_0;
use dist_primitive::{
    mle::PackedDenseMultilinearExtension, utils::serializing_net::MPCSerializeNet,
};
use futures::future::try_join_all;
use mpc_net::{MPCNet, MPCNetError, MultiplexedStreamID};

use rand::random;
use secret_sharing::pss::PackedSharingParams;
use std::hint::black_box;

use std::{collections::HashMap, ops::Mul};
pub struct SparseMultilinearExtension<F>(pub HashMap<(F, F, F), F>);

/// f1(g,x,y)f2(x)f3(y)
pub async fn d_gkr_round<F: FftField, Net: MPCSerializeNet>(
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
    // TROUBLE: how do we get g? How do we calculate phase one and two?
    let hg = d_initialize_phase_one(shares_f1, shares_f3, challenge_g, pp, net, sid).await?;
    let mut proof1 =
        d_sumcheck_product(&hg.shares, &shares_f2.shares, challenge_u, pp, net, sid).await?;
    let f1 = d_initialize_phase_two(shares_f1, challenge_g, challenge_v, pp, net, sid).await?;
    // TROUBLE: here we need to multiply f3 with f2(u), this could be costly.
    let f2_u = d_fix_variable(&shares_f2.shares, challenge_u, pp, net, sid).await?[0];
    let f2_u = d_unpack_0(f2_u, pp, net, sid).await?;
    let shares_f3_f2u = shares_f3.mul(&f2_u);
    let proof2 =
        d_sumcheck_product(&f1.shares, &shares_f3_f2u.shares, challenge_v, pp, net, sid).await?;
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
    // Now this comes from Father Christmas
    black_box(shares_f1);
    black_box(shares_f3);
    black_box(challenge_g);
    d_polyfill_phase_initilization(shares_f1, pp, net, sid).await?;
    Ok(PackedDenseMultilinearExtension::from_evaluations_slice(
        challenge_g.len(),
        &vec![F::zero(); 1 << challenge_g.len() - pp.l.trailing_zeros() as usize],
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
    d_polyfill_phase_initilization(shares_f1, pp, net, sid).await?;
    Ok(PackedDenseMultilinearExtension::from_evaluations_slice(
        challenge_g.len(),
        &vec![F::zero(); 1 << challenge_g.len() - pp.l.trailing_zeros() as usize],
    ))
}

pub async fn d_polyfill_phase_initilization<F: FftField, Net: MPCSerializeNet>(
    shares_f1: &SparseMultilinearExtension<F>,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<(), MPCNetError> {
    // Handle each point in f1, we only got 1/N of the points so the rest have to be retrieved from other parties.
    // We need to run n d_perm and n degree_reduce.
    // Besides, only 1/N computations should be done on party 0
    let simulation = {
        let share: Vec<F> = pp.pack_from_public(vec![F::zero(); pp.l]);
        let reduced_shares: Vec<_> = (0..shares_f1.0.len())
            .map(|_| degree_reduce(black_box(share[0]) * black_box(share[0]), pp, net, sid))
            .collect();
        try_join_all(reduced_shares).await?
    };
    black_box(simulation);
    // // Fill up the omitted comms for f1 shares, these hash map entries are transmitted from and to other parties
    // let transmit: Vec<(usize, usize, usize)> = (0..shares_f1.0.len()).map(|x| (x, x, x)).collect();
    // let mut bytes_out = Vec::new();
    // transmit.serialize_uncompressed(&mut bytes_out)?;
    // let size = bytes_out.len();
    // net.add_comm(size * (net.n_parties() - 1), size * (net.n_parties() - 1));
    Ok(())
}

static CNT: AtomicUsize = AtomicUsize::new(0);

/// The result is a miraculous triple Vec.
/// The first Vec arranges the result for each layer
/// The second Vec arranges 3 proofs for one layer
pub async fn d_polyfill_gkr<E: Pairing, Net: MPCSerializeNet>(
    layer_cnt: usize,
    layer_width: usize,
    shares_f1: &SparseMultilinearExtension<E::ScalarField>,
    shares_f2: &PackedDenseMultilinearExtension<E::ScalarField>,
    shares_f3: &PackedDenseMultilinearExtension<E::ScalarField>,
    challenge_g: &Vec<E::ScalarField>,
    challenge_u: &Vec<E::ScalarField>,
    challenge_v: &Vec<E::ScalarField>,
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
    // In each round we actually need to run 3 sub-gkr-rounds.
    // 1 complete rounds, with form f1(g,x,y)f2(x)f3(y)
    // 2 incomplete rounds, 1 with form f1(g,x,y)f2(x) and 1 with form f1(g,x,y)f3(y)
    // We can handle the 2 incomplete rounds as if we have f2(x) \equiv 1 and f3(y) \equiv 1
    // So at last we run 3 polyfill gkr rounds in each layer.
    let mut proof = Vec::new();
    let rng = &mut ark_std::test_rng();

    let order = CNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let reporter = order == pp.l * 4 - 1;
    let timer_all = start_timer!("Begin dGKR", reporter);
    let commit = timed!(
        "dCommit",
        mature.d_commit(&shares_f2.shares, pp, net, sid).await?,
        reporter
    );
    let timer_gkr_rounds = start_timer!("dGKR rounds", reporter);
    for _ in 0..layer_cnt {
        let mut layer_proof = Vec::new();
        for _ in 0..3 {
            layer_proof.push(
                d_gkr_round(
                    black_box(&shares_f1),
                    black_box(&shares_f2),
                    black_box(&shares_f3),
                    black_box(&challenge_g),
                    black_box(&challenge_u),
                    black_box(&challenge_v),
                    pp,
                    net,
                    sid,
                )
                .await?,
            );
        }
        if reporter {
            println!("Comm: {:?}", net.get_comm());
        }
        proof.push(layer_proof);
    }
    end_timer!(timer_gkr_rounds);
    let s = (0..layer_width)
        .map(|_| E::ScalarField::rand(rng))
        .collect::<Vec<_>>();
    let open = timed!(
        "dOpen",
        mature.d_open(&shares_f2.shares, &s, pp, net, sid).await?,
        reporter
    );

    end_timer!(timer_all);
    Ok((proof, commit, open))
}

/// f1(g,x,y)f2(x)f3(y)
pub fn gkr_round<F: FftField>(
    f1: &SparseMultilinearExtension<F>,
    f2: &DenseMultilinearExtension<F>,
    f3: &DenseMultilinearExtension<F>,
    challenge_g: &Vec<F>,
    challenge_u: &Vec<F>,
    challenge_v: &Vec<F>,
) -> Vec<(F, F, F)> {
    // TROUBLE: how do we get g? How do we calculate phase one and two?
    let hg = initialize_phase_one(f1, f3, challenge_g);
    let mut proof1 = sumcheck_product(&hg.evaluations, &f2.evaluations, challenge_u);
    let f1 = initialize_phase_two(f1, challenge_g, challenge_v);
    // TROUBLE: here we need to multiply f3 with f2(u), this could be costly.
    let f2_u = fix_variable(&f2.evaluations, challenge_u)[0];
    let f3_f2u = f3.mul(&f2_u);
    let proof2 = sumcheck_product(&f1.evaluations, &f3_f2u.evaluations, challenge_v);
    proof1.extend(proof2);
    proof1
}

pub fn initialize_phase_one<F: FftField>(
    f1: &SparseMultilinearExtension<F>,
    f3: &DenseMultilinearExtension<F>,
    challenge_g: &Vec<F>,
) -> DenseMultilinearExtension<F> {
    // Now this comes from Father Christmas
    black_box(f1);
    black_box(f3);
    black_box(challenge_g);
    polyfill_phase_initilization(f1)
}

pub fn initialize_phase_two<F: FftField>(
    f1: &SparseMultilinearExtension<F>,
    challenge_g: &Vec<F>,
    challenge_v: &Vec<F>,
) -> DenseMultilinearExtension<F> {
    // Now this comes from Father Christmas
    black_box(f1);
    black_box(challenge_g);
    black_box(challenge_v);
    polyfill_phase_initilization(f1)
}

pub fn polyfill_phase_initilization<F: FftField>(
    f1: &SparseMultilinearExtension<F>,
) -> DenseMultilinearExtension<F> {
    let mut evaluations = vec![F::zero(); f1.0.len()];
    let _simulation = {
        for (_k, v) in &f1.0 {
            evaluations[random::<usize>() % f1.0.len()] += v;
        }
    };
    DenseMultilinearExtension::from_evaluations_slice(f1.0.len(), &evaluations)
}

pub fn polyfill_gkr<E: Pairing>(
    layer_cnt: usize,
    layer_width: usize,
) -> (
    Vec<Vec<Vec<(E::ScalarField, E::ScalarField, E::ScalarField)>>>,
    E::G1,
    (E::ScalarField, Vec<E::G1>),
) {
    // In each round we actually need to run 3 sub-gkr-rounds.
    // 1 complete rounds, with form f1(g,x,y)f2(x)f3(y)
    // 2 incomplete rounds, 1 with form f1(g,x,y)f2(x) and 1 with form f1(g,x,y)f3(y)
    // We can handle the 2 incomplete rounds as if we have f2(x) \equiv 1 and f3(y) \equiv 1
    // So at last we run 3 polyfill gkr rounds in each layer.
    let mut proof = Vec::new();
    let rng = &mut ark_std::test_rng();
    let mut f1 = SparseMultilinearExtension::<E::ScalarField>(HashMap::new());
    // Randomly generate these shares and challenges for new
    for _ in 0..(1 << layer_width) {
        f1.0.insert(
            (
                E::ScalarField::rand(rng),
                E::ScalarField::rand(rng),
                E::ScalarField::rand(rng),
            ),
            E::ScalarField::rand(rng),
        );
    }
    let f2 = DenseMultilinearExtension::from_evaluations_slice(
        0,
        &(0..(1 << layer_width))
            .map(|_| E::ScalarField::rand(rng))
            .collect::<Vec<_>>(),
    );

    let f3 = DenseMultilinearExtension::from_evaluations_slice(
        0,
        &(0..(1 << layer_width))
            .map(|_| E::ScalarField::rand(rng))
            .collect::<Vec<_>>(),
    );
    let challenge_g: Vec<E::ScalarField> = (0..layer_width)
        .map(|_| E::ScalarField::rand(rng))
        .collect::<Vec<_>>();
    let challenge_u: Vec<E::ScalarField> = (0..layer_width)
        .map(|_| E::ScalarField::rand(rng))
        .collect::<Vec<_>>();
    let challenge_v: Vec<E::ScalarField> = (0..layer_width)
        .map(|_| E::ScalarField::rand(rng))
        .collect::<Vec<_>>();

    let g1 = E::G1::rand(rng);
    let g2 = E::G2::rand(rng);
    let s = (0..layer_width as usize)
        .map(|_| E::ScalarField::rand(rng))
        .collect::<Vec<_>>();
    let cub = PolynomialCommitmentCub::<E>::new(g1, g2, s);
    let mature = cub.mature();
    let timer_all = start_timer!("Begin GKR");
    let commit = timed!("Commit", mature.commit(&f2.evaluations));
    let timer_gkr_rounds = start_timer!("GKR rounds");
    for _ in 0..layer_cnt {
        let mut layer_proof = Vec::new();
        for _ in 0..3 {
            layer_proof.push(gkr_round(
                black_box(&f1),
                black_box(&f2),
                black_box(&f3),
                black_box(&challenge_g),
                black_box(&challenge_u),
                black_box(&challenge_v),
            ));
        }
        proof.push(layer_proof);
    }
    end_timer!(timer_gkr_rounds);
    let u = (0..layer_width)
        .map(|_| E::ScalarField::rand(rng))
        .collect::<Vec<_>>();
    let timer_open = start_timer!("Open");
    let (value, com_proof) = mature.open(&f2.evaluations, &u);
    end_timer!(timer_open);
    end_timer!(timer_all);
    assert!(mature.verify(commit, value, &com_proof, &u));
    (proof, commit, (value, com_proof))
}

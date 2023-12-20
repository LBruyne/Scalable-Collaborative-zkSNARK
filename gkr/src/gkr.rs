use ark_ec::pairing::Pairing;
use ark_ff::FftField;
use ark_serialize::CanonicalSerialize;
use ark_std::One;
use ark_std::UniformRand;
use ark_std::Zero;
use dist_primitive::degree_reduce::degree_reduce;
use dist_primitive::dperm::d_perm;
use dist_primitive::dpoly_comm::PolynomialCommitmentCub;
use dist_primitive::dsumcheck::d_sumcheck_product;
use dist_primitive::mle::d_fix_variable;
use dist_primitive::unpack::d_unpack_0;
use dist_primitive::{
    mle::PackedDenseMultilinearExtension, utils::serializing_net::MPCSerializeNet,
};
use futures::future::try_join_all;
use mpc_net::{MPCNet, MPCNetError, MultiplexedStreamID};

use secret_sharing::pss::PackedSharingParams;
use std::{collections::HashMap, ops::Mul};

pub struct SparseMultilinearExtension<F>(HashMap<(F, F, F), F>);

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
    _shares_f3: &PackedDenseMultilinearExtension<F>,
    challenge_g: &Vec<F>,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<PackedDenseMultilinearExtension<F>, MPCNetError> {
    // Now this comes from Father Christmas
    d_polyfill_phase_initilization(shares_f1, pp, net, sid).await?;
    Ok(PackedDenseMultilinearExtension::from_evaluations_slice(
        challenge_g.len(),
        &vec![F::zero(); 1 << challenge_g.len()],
    ))
}

pub async fn d_initialize_phase_two<F: FftField, Net: MPCSerializeNet>(
    shares_f1: &SparseMultilinearExtension<F>,
    challenge_g: &Vec<F>,
    _challenge_v: &Vec<F>,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<PackedDenseMultilinearExtension<F>, MPCNetError> {
    // Now this comes from Father Christmas
    d_polyfill_phase_initilization(shares_f1, pp, net, sid).await?;
    Ok(PackedDenseMultilinearExtension::from_evaluations_slice(
        challenge_g.len(),
        &vec![F::zero(); 1 << challenge_g.len()],
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
    let permutation = (0..1 << pp.l).collect();
    let _simulation = {
        let share: Vec<F> = pp.pack_from_public_rand(vec![]);
        let permuted_shares: Vec<_> = (0..pp.l * shares_f1.0.len() / net.n_parties())
            .map(|_| d_perm(share[0], &permutation, pp, net, sid))
            .collect();
        let reduced_shares: Vec<_> = try_join_all(permuted_shares)
            .await?
            .iter()
            .map(|s| degree_reduce(*s * *s, pp, net, sid))
            .collect();
        try_join_all(reduced_shares).await?
    };
    // Fill up the omitted comms for f1 shares, these hash map entries are transmitted from and to other parties
    let transmit: Vec<(usize, usize, usize)> = (0..shares_f1.0.len()).map(|x| (x, x, x)).collect();
    let mut bytes_out = Vec::new();
    transmit.serialize_uncompressed(&mut bytes_out)?;
    let size = bytes_out.len();
    net.add_comm(size * (net.n_parties() - 1), size * (net.n_parties() - 1));
    // Fill up the omitted comms for computation in which party 0 is not the leader, which is n*(N-1)/N d_perm and degree reduce, 2*n*(N-1)/N shares in total
    let share: Vec<F> = pp.pack_from_public_rand(vec![]);
    let mut bytes_out = Vec::new();
    share.serialize_uncompressed(&mut bytes_out)?;
    let size = bytes_out.len();
    net.add_comm(
        2 * size * pp.l * shares_f1.0.len() * (net.n_parties() - 1) / net.n_parties(),
        2 * size * pp.l * shares_f1.0.len() * (net.n_parties() - 1) / net.n_parties(),
    );
    Ok(())
}

/// The result is a miraculous triple Vec.
/// The first Vec arranges the result for each layer
/// The second Vec arranges 3 proofs for one layer
pub async fn d_polyfill_gkr<E: Pairing, Net: MPCSerializeNet>(
    layer_cnt: usize,
    layer_width: usize,
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
    let mut shares_f1 = SparseMultilinearExtension::<E::ScalarField>(HashMap::new());
    // Randomly generate these shares and challenges for new
    for _ in 0..1 << layer_width {
        shares_f1.0.insert(
            (
                E::ScalarField::rand(rng),
                E::ScalarField::rand(rng),
                E::ScalarField::rand(rng),
            ),
            E::ScalarField::one(),
        );
    }
    let shares_f2 = PackedDenseMultilinearExtension::<E::ScalarField>::from_evaluations_slice(
        1 << layer_width,
        &vec![E::ScalarField::zero(); 1 << layer_width],
    );
    let shares_f3 = PackedDenseMultilinearExtension::<E::ScalarField>::from_evaluations_slice(
        1 << layer_width,
        &vec![E::ScalarField::zero(); 1 << layer_width],
    );
    let challenge_g: Vec<E::ScalarField> = vec![E::ScalarField::zero(); 1 << layer_width];
    let challenge_u: Vec<E::ScalarField> = vec![E::ScalarField::zero(); 1 << layer_width];
    let challenge_v: Vec<E::ScalarField> = vec![E::ScalarField::zero(); 1 << layer_width];

    let g1 = E::G1::rand(rng);
    let g2 = E::G2::rand(rng);
    let s = (0..layer_width - pp.l.trailing_zeros() as usize)
        .map(|_| E::ScalarField::rand(rng))
        .collect::<Vec<_>>();
    let cub = PolynomialCommitmentCub::<E>::new(g1, g2, s);
    let mature = cub.mature();
    let commit = mature.d_commit(&shares_f2.shares, pp, net, sid).await?;

    println!("cub done");

    for _ in 0..layer_cnt {
        let mut layer_proof = Vec::new();
        for _ in 0..3 {
            layer_proof.push(
                d_gkr_round(
                    &shares_f1,
                    &shares_f2,
                    &shares_f3,
                    &challenge_g,
                    &challenge_u,
                    &challenge_v,
                    pp,
                    net,
                    sid,
                )
                .await?,
            );
        }

        proof.push(layer_proof);
    }
    let s = (0..layer_width)
        .map(|_| E::ScalarField::rand(rng))
        .collect::<Vec<_>>();
    let open = mature.d_open(&shares_f2.shares, &s, pp, net, sid).await?;
    Ok((proof, commit, open))
}

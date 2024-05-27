use crate::utils::{operator::transpose, serializing_net::MPCSerializeNet};
use ark_ec::CurveGroup;

use mpc_net::{end_timer, start_timer};
use mpc_net::{MPCNetError, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;

/// This protocol implement dMSM in a batched way. 
pub async fn d_msm<G: CurveGroup, Net: MPCSerializeNet>(
    bases: &Vec<Vec<G::Affine>>,
    scalars: &Vec<Vec<G::ScalarField>>,
    pp: &PackedSharingParams<G::ScalarField>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<Vec<G>, MPCNetError> {
    assert_eq!(bases.len(), scalars.len());
    // Obtain the result of each dMSM.
    let msm_timer = start_timer!("Local: MSM", net.is_leader());
    let c_shares = bases.iter().zip(scalars.iter()).map(|(b, s)| {
        // if net.is_leader() {
        //     eprintln!("MSM len: {}, {}", s.len(), b.len());
        // }
        G::msm(b, s).unwrap()
    }).collect::<Vec<_>>();
    end_timer!(msm_timer);

    let leader_timer = start_timer!("Send to leader for MSM", net.is_leader());
    // Should be masked by randoms. Omitted for simplicity.
    let result = net.leader_compute_element(&c_shares, sid, |shares|{
        let shares = transpose(shares);
        let results = shares.iter().map(|s| {
            // This operation is costing for single-threaded execution. In the benchmark statistic, we assume this `iter` opertion can be replaced by a `par_iter` for parallelism. This is reasonable as in practice leader can use rayon to parallelize the computation.
            let binding = pp.unpack2(s.clone());
            let output = binding.iter().sum();
            let pack = vec![output;pp.l];
            let res = pp.pack_from_public(pack);
            res
        }).collect();
        transpose(results)
    }, "MSM Leader").await;
    end_timer!(leader_timer);
    return result;
}

#[cfg(test)]
mod tests {
    use ark_ec::bls12::Bls12Config;
    use ark_ec::CurveGroup;
    use ark_ec::Group;
    use ark_ec::VariableBaseMSM;
    use ark_std::UniformRand;
    use ark_std::Zero;
    use secret_sharing::pss::PackedSharingParams;

    use ark_bls12_377::G1Affine;
    use ark_bls12_377::G1Projective as G1P;
    use mpc_net::LocalTestNet;

    type F = <ark_ec::short_weierstrass::Projective<
        <ark_bls12_377::Config as Bls12Config>::G1Config,
    > as Group>::ScalarField;

    // use crate::dmsm::packexp_from_public;
    // use crate::dmsm::unpackexp;
    use crate::utils::operator::transpose;

    const L: usize = 2;
    const N: usize = L * 4;
    // const T:usize = N/2 - L - 1;
    const M: usize = 1 << 8;

    #[tokio::test]
    async fn pack_unpack_test() {
        println!("pack_unpack_test");
        let net = LocalTestNet::new_local_testnet(4).await.unwrap();

        println!("net init done");

        net.simulate_network_round((), |_, _| async move {
            let pp = PackedSharingParams::<F>::new(L);
            let rng = &mut ark_std::test_rng();
            let secrets: [G1P; L] = UniformRand::rand(rng);
            let secrets = secrets.to_vec();

            let shares = pp.pack_from_public(secrets.clone());
            let result = pp.unpack(shares);
            assert_eq!(secrets, result);
        })
        .await;
    }

    #[tokio::test]
    async fn pack_unpack2_test() {
        let net = LocalTestNet::new_local_testnet(4).await.unwrap();

        net.simulate_network_round((), |_, _| async move {
            let pp = PackedSharingParams::<F>::new(L);
            let rng = &mut ark_std::test_rng();

            let gsecrets: [G1P; M] = [G1P::rand(rng); M];
            let gsecrets = gsecrets.to_vec();

            let fsecrets: [F; M] = [F::from(1_u32); M];
            let fsecrets = fsecrets.to_vec();

            ///////////////////////////////////////
            let gsecrets_aff: Vec<G1Affine> =
                gsecrets.iter().map(|s| (*s).into()).collect();
            let expected = G1P::msm(&gsecrets_aff, &fsecrets).unwrap();
            ///////////////////////////////////////
            let gshares: Vec<Vec<G1P>> = gsecrets
                .chunks(L)
                .map(|s| pp.pack_from_public(s.to_vec()))
                .collect();

            let fshares: Vec<Vec<F>> = fsecrets
                .chunks(L)
                .map(|s| pp.pack_from_public(s.to_vec()))
                .collect();

            let gshares = transpose(gshares);
            let fshares = transpose(fshares);

            let mut result = vec![G1P::zero(); N];

            for i in 0..N {
                let temp_aff: Vec<
                    <ark_ec::short_weierstrass::Projective<
                        <ark_bls12_377::Config as Bls12Config>::G1Config,
                    > as CurveGroup>::Affine,
                > = gshares[i].iter().map(|s| (*s).into()).collect();
                result[i] = G1P::msm(&temp_aff, &fshares[i]).unwrap();
            }
            let result: G1P = pp.unpack2(result).iter().sum();
            assert_eq!(expected, result);
        })
        .await;
    }
}

use crate::{utils::serializing_net::MPCSerializeNet, end_timer, start_timer};
use ark_ec::CurveGroup;

use mpc_net::{MPCNetError, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;

pub async fn d_msm<G: CurveGroup, Net: MPCSerializeNet>(
    bases: &[G::Affine],
    scalars: &[G::ScalarField],
    pp: &PackedSharingParams<G::ScalarField>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<G, MPCNetError> {
    // Using affine is important because we don't want to create an extra vector for converting Projective to Affine.
    // Eventually we do have to convert to Projective but this will be pp.l group elements instead of m()

    // First round of local computation done by parties
    log::debug!("bases: {}, scalars: {}", bases.len(), scalars.len());
    let timer1 = start_timer!("calculate_msm", !net.is_leader());
    let c_share = G::msm(bases, scalars).unwrap();
    end_timer!(timer1);
    // Now we do degree reduction -- psstoss
    // Send to king who reduces and sends shamir shares (not packed).
    // Should be randomized. First convert to projective share.
    log::warn!("Distributed MSM protocol should be masked by random sharing. Omitted for simplicity.");
    let n_parties = net.n_parties();
    net.leader_compute_element(&c_share, sid, |shares|{
        let timer2 = start_timer!("leader calculation");
        let output: G = pp.unpack2(shares).iter().sum();
        end_timer!(timer2);
        vec![output; n_parties]
    }).await
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

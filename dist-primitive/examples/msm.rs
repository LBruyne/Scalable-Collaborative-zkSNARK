#![feature(thread_id_value)]
use ark_bls12_381::Fr;
use rayon::prelude::*;
use ark_ec::{bls12::Bls12, pairing::Pairing, CurveGroup, VariableBaseMSM};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::UniformRand;
use dist_primitive::{dmsm::d_msm, utils::operator::transpose};
use mpc_net::{end_timer, start_timer};
use mpc_net::{LocalTestNet as Net, MPCNet, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;

const L: usize = 8;
const N: usize = 16;
type E = Bls12<ark_bls12_381::Config>;
#[cfg_attr(feature = "single_thread", tokio::main(flavor = "current_thread"))]
#[cfg_attr(not(feature = "single_thread"), tokio::main)]
async fn main() {
    for i in N..=N {
        let pp = PackedSharingParams::<Fr>::new(L);
        let _rng = &mut ark_std::test_rng();
        let dom = Radix2EvaluationDomain::<Fr>::new(1 << i).unwrap();

        let mut y_pub = Vec::new();
        let mut x_pub: Vec<<E as Pairing>::G1> = Vec::new();
        for _ in 0..dom.size() {
            y_pub.push(<E as Pairing>::ScalarField::rand(_rng));
            x_pub.push(<E as Pairing>::G1::rand(_rng));
        }
        let x_aff: Vec<_> = x_pub.par_iter().map(|x| x.into_affine()).collect();

        let x_share: Vec<Vec<<E as Pairing>::G1Affine>> = transpose(
            x_pub
                .chunks_exact(pp.l)
                .map(|s| {
                    pp.pack_from_public(s.to_vec())
                        .into_par_iter()
                        .map(|x| x.into())
                        .collect::<Vec<_>>()
                })
                .collect(),
        );

        let y_share = transpose(
            y_pub
                .chunks(pp.l)
                .map(|s| pp.pack_from_public(s.to_vec()))
                .collect::<Vec<_>>(),
        );

        // Ark msm
        eprintln!("Ark msm len: {}", y_pub.len());
        let nmsm = start_timer!("Ark msm");
        let _should_be_output =
            <Bls12<ark_bls12_381::Config> as Pairing>::G1::msm(x_aff.as_slice(), &y_pub.as_slice())
                .unwrap();
        end_timer!(nmsm);

        // Distributed msm
        let network = Net::new_local_testnet(L * 4).await.unwrap();
        network
            .simulate_network_round(
                (x_share, y_share),
                move |net, (x_share, y_share)| async move {
                    let pp = PackedSharingParams::<Fr>::new(L);
                    let _ = Radix2EvaluationDomain::<Fr>::new(1 << i).unwrap();
                    d_msm_test::<<E as Pairing>::G1, _>(
                        &pp,
                        &x_share[net.party_id() as usize],
                        &y_share[net.party_id() as usize],
                        &net,
                    )
                    .await;
                },
            )
            .await;
    }
}

pub async fn d_msm_test<G: CurveGroup, Net: MPCNet>(
    pp: &PackedSharingParams<G::ScalarField>,
    x_share_aff: &Vec<G::Affine>,
    y_share: &Vec<G::ScalarField>,
    net: &Net,
) {
    if net.is_leader() {
        eprintln!("Distributed msm len: {}", x_share_aff.len());
    }
    let dmsm = start_timer!("Distributed msm", net.is_leader());
    let _output = d_msm::<G, Net>(
        &vec![x_share_aff.clone()],
        &vec![y_share.clone()],
        pp,
        net,
        MultiplexedStreamID::Zero,
    )
    .await;
    end_timer!(dmsm);
    if net.is_leader() {
        println!("Comm: {:?}", net.get_comm());
    }
}

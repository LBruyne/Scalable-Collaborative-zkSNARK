#![feature(thread_id_value)]
use std::sync::atomic::AtomicU32;
use ark_std::Zero;
use ark_bls12_377::Fr;
use ark_ec::CurveGroup;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

use dist_primitive::{dmsm::d_msm, end_timer, start_timer};
use mpc_net::{LocalTestNet as Net, MPCNet, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;

const L: usize = 4;
const N: usize = 20;
static CNT: AtomicU32 = AtomicU32::new(0);
/// Note that the output of the function is misleading. The threads are not synchronized. So the plain msm is accurately timed, but only the last thread that start d_msm will yield a meaningful result. The time output of the other threads are meaningless since they are mostly waiting for the last thread to be ready.
pub async fn d_msm_test<G: CurveGroup, Net: MPCNet>(
    pp: &PackedSharingParams<G::ScalarField>,
    dom: &Radix2EvaluationDomain<G::ScalarField>,
    net: &Net,
) {
    // let m = pp.l*4;
    // let case_timer = start_timer!(||"affinemsm_test");
    let _mbyl: usize = dom.size() / pp.l;
    // println!("m: {}, mbyl: {}", dom.size(), mbyl);

    let _rng = &mut ark_std::test_rng();

    let mut y_pub: Vec<G::ScalarField> = Vec::new();
    let mut x_pub: Vec<G> = Vec::new();

    for _ in 0..dom.size() {
        // y_pub.push(G::ScalarField::rand(rng));
        // x_pub.push(G::rand(rng));
        y_pub.push(G::ScalarField::zero());
        x_pub.push(G::zero());
    }

    let x_share: Vec<G> = x_pub
        .chunks(pp.l)
        .map(|s| pp.pack_from_public(s.to_vec())[net.party_id() as usize])
        .collect();

    let y_share: Vec<G::ScalarField> = y_pub
        .chunks(pp.l)
        .map(|s| pp.pack_from_public(s.to_vec())[net.party_id() as usize])
        .collect();

    let x_pub_aff: Vec<G::Affine> = x_pub.iter().map(|s| s.clone().into()).collect();
    let x_share_aff: Vec<G::Affine> = x_share.iter().map(|s| s.clone().into()).collect();

    // Will be comparing against this in the end
    let nmsm = start_timer!("Ark msm", net.is_leader());
    let _should_be_output = G::msm(&x_pub_aff.as_slice(), &y_pub.as_slice()).unwrap();
    end_timer!(nmsm);
    let order = CNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let ready = order == (L * 4 - 1).try_into().unwrap();
    let dmsm = start_timer!("Distributed msm", ready);
    let _output = d_msm::<G, Net>(&x_share_aff, &y_share, pp, net, MultiplexedStreamID::Zero).await;
    end_timer!(dmsm);
    if net.is_leader() {
        println!("Comm: {:?}", net.get_comm());
    }
}

#[tokio::main]
async fn main() {
    env_logger::builder().init();

    for i in N..=N {
        let dom = Radix2EvaluationDomain::<Fr>::new(1 << i).unwrap();
        println!("domain size: {}", dom.size());
        // msm_test::<ark_bls12_377::G1Projective>(&dom);

        let network = Net::new_local_testnet(L * 4).await.unwrap();
        network
            .simulate_network_round((), move |net, _| async move {
                let pp = PackedSharingParams::<Fr>::new(L);
                let dom = Radix2EvaluationDomain::<Fr>::new(1 << i).unwrap();
                d_msm_test::<ark_bls12_377::G1Projective, _>(&pp, &dom, &net).await;
            })
            .await;
    }
}

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use async_trait::async_trait;

use mpc_net::{MPCNet, MPCNetError, MultiplexedStreamID};

use crate::{start_timer, end_timer};

/// The MPC net can serialize and deserialize elements. Should be useful for arkworks computation.
#[async_trait]
pub trait MPCSerializeNet: MPCNet {
    async fn worker_send_or_leader_receive_element<T: CanonicalDeserialize + CanonicalSerialize>(
        &self,
        out: &T,
        sid: MultiplexedStreamID,
    ) -> Result<Option<Vec<T>>, MPCNetError> {
        let mut bytes_out = Vec::new();
        out.serialize_uncompressed(&mut bytes_out).unwrap();
        let bytes_in = self.worker_send_or_leader_receive(&bytes_out, sid).await?;
        if let Some(bytes_in) = bytes_in {
            // This is leader
            debug_assert!(self.is_leader());
            let results: Vec<Result<T, MPCNetError>> = bytes_in
                .into_iter()
                .map(|b| {
                    T::deserialize_uncompressed_unchecked(&b[..])
                        .map_err(|err| MPCNetError::Generic(err.to_string()))
                })
                .collect();

            let mut ret = Vec::new();
            for result in results {
                ret.push(result?);
            }

            Ok(Some(ret))
        } else {
            Ok(None)
        }
    }

    async fn worker_receive_or_leader_send_element<
        T: CanonicalDeserialize + CanonicalSerialize + Send,
        // A bug of rustc, T does not have to be Send actually. See https://github.com/rust-lang/rust/issues/63768
    >(
        &self,
        out: Option<Vec<T>>,
        sid: MultiplexedStreamID,
    ) -> Result<T, MPCNetError> {
        let bytes = out.map(|outs| {
            outs.iter()
                .map(|out| {
                    let mut bytes_out = Vec::new();
                    out.serialize_uncompressed(&mut bytes_out).unwrap();
                    bytes_out.into()
                })
                .collect()
        });

        let bytes_in = self.worker_receive_or_leader_send(bytes, sid).await?;
        Ok(T::deserialize_uncompressed_unchecked(&bytes_in[..])?)
    }

    /// Everyone sends bytes to the leader, who receives those bytes, runs a computation on them, and
    /// redistributes the resulting bytes.
    ///
    /// The leader's computation is given by a function, `f`
    /// proceeds.
    async fn leader_compute_element<T: CanonicalDeserialize + CanonicalSerialize + Send>(
        &self,
        out: &T,
        sid: MultiplexedStreamID,
        f: impl Fn(Vec<T>) -> Vec<T> + Send,
    ) -> Result<T, MPCNetError> {
        let leader_response = self
            .worker_send_or_leader_receive_element(out, sid)
            .await?
            .map(f);
        self.worker_receive_or_leader_send_element(leader_response, sid)
            .await
    }
}

impl<N: MPCNet> MPCSerializeNet for N {}

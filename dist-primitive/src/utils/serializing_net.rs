use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use async_trait::async_trait;

use mpc_net::{MPCNet, MPCNetError, MultiplexedStreamID};
use mpc_net::{end_timer, start_timer};

/// The MPC net can serialize and deserialize elements. Should be useful for arkworks computation.
#[cfg(feature = "comm")]
#[async_trait]
pub trait MPCSerializeNet: MPCNet {
    async fn worker_send_or_leader_receive_element<T: CanonicalDeserialize + CanonicalSerialize>(
        &self,
        out: &T,
        sid: MultiplexedStreamID,
    ) -> Result<Option<Vec<T>>, MPCNetError> {
        let mut bytes_out = Vec::new();
        out.serialize_compressed(&mut bytes_out).unwrap();
        let bytes_in = self.worker_send_or_leader_receive(&bytes_out, sid).await?;
        if let Some(bytes_in) = bytes_in {
            // This is leader
            debug_assert!(self.is_leader());
            let results: Vec<Result<T, MPCNetError>> = bytes_in
                .into_iter()
                .map(|b| {
                    T::deserialize_compressed(&b[..])
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

    async fn dynamic_worker_send_or_leader_receive_element<
        T: CanonicalDeserialize + CanonicalSerialize,
    >(
        &self,
        out: &T,
        receiver: u32,
        sid: MultiplexedStreamID,
    ) -> Result<Option<Vec<T>>, MPCNetError> {
        let mut bytes_out = Vec::new();
        out.serialize_compressed(&mut bytes_out).unwrap();
        let bytes_in = self
            .dynamic_worker_send_or_leader_receive(&bytes_out, receiver, sid)
            .await?;
        if let Some(bytes_in) = bytes_in {
            // This is leader
            debug_assert!(receiver == self.party_id());
            let results: Vec<Result<T, MPCNetError>> = bytes_in
                .into_iter()
                .map(|b| {
                    T::deserialize_compressed(&b[..])
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
                    out.serialize_compressed(&mut bytes_out).unwrap();
                    bytes_out.into()
                })
                .collect()
        });

        let bytes_in = self.worker_receive_or_leader_send(bytes, sid).await?;
        Ok(T::deserialize_compressed(&bytes_in[..])?)
    }

    async fn dynamic_worker_receive_or_worker_send_element<
        T: CanonicalDeserialize + CanonicalSerialize + Send,
        // A bug of rustc, T does not have to be Send actually. See https://github.com/rust-lang/rust/issues/63768
    >(
        &self,
        out: Option<Vec<T>>,
        sender: u32,
        sid: MultiplexedStreamID,
    ) -> Result<T, MPCNetError> {
        let bytes = out.map(|outs| {
            outs.iter()
                .map(|out| {
                    let mut bytes_out = Vec::new();
                    out.serialize_compressed(&mut bytes_out).unwrap();
                    bytes_out.into()
                })
                .collect()
        });

        let bytes_in = self
            .dynamic_worker_receive_or_leader_send(bytes, sender, sid)
            .await?;
        Ok(T::deserialize_compressed(&bytes_in[..])?)
    }

    /// Everyone sends bytes to the leader, who receives those bytes, runs a computation on them, and
    /// redistributes the resulting bytes.
    ///
    /// The leader's computation is given by a function, `f`
    /// proceeds.
    async fn leader_compute_element<T: CanonicalDeserialize + CanonicalSerialize + Send + Clone>(
        &self,
        out: &T,
        sid: MultiplexedStreamID,
        f: impl Fn(Vec<T>) -> Vec<T> + Send,
        for_what: &str,
    ) -> Result<T, MPCNetError> {
        let leader_response = self.worker_send_or_leader_receive_element(out, sid).await?;
        let timer = start_timer!(format!("Leader: Compute element ({})", for_what), self.is_leader());
        let leader_response = leader_response.map(f);
        end_timer!(timer);
        self.worker_receive_or_leader_send_element(leader_response, sid)
            .await
    }
}

#[cfg(not(feature = "comm"))]
#[async_trait]
pub trait MPCSerializeNet: MPCNet {
    async fn worker_send_or_leader_receive_element<
        T: CanonicalDeserialize + CanonicalSerialize + Clone,
    >(
        &self,
        out: &T,
        _sid: MultiplexedStreamID,
    ) -> Result<Option<Vec<T>>, MPCNetError> {
        let mut bytes_out = Vec::new();
        out.serialize_compressed(&mut bytes_out).unwrap();
        if self.is_leader() {
            // This is leader
            self.add_comm(0, bytes_out.len() * (self.n_parties() - 1));
            Ok(Some(vec![
                T::deserialize_compressed(&bytes_out[..])?;
                self.n_parties()
            ]))
        } else {
            self.add_comm(bytes_out.len(), 0);
            Ok(None)
        }
    }

    async fn dynamic_worker_send_or_leader_receive_element<
        T: CanonicalDeserialize + CanonicalSerialize + Clone,
    >(
        &self,
        out: &T,
        receiver: u32,
        _sid: MultiplexedStreamID,
    ) -> Result<Option<Vec<T>>, MPCNetError> {
        let mut bytes_out = Vec::new();
        out.serialize_compressed(&mut bytes_out).unwrap();
        if receiver == self.party_id() {
            // This is leader
            self.add_comm(0, bytes_out.len() * (self.n_parties() - 1));
            Ok(Some(vec![
                T::deserialize_compressed(&bytes_out[..])?;
                self.n_parties()
            ]))
        } else {
            self.add_comm(bytes_out.len(), 0);
            Ok(None)
        }
    }

    async fn worker_receive_or_leader_send_element<
        T: CanonicalDeserialize + CanonicalSerialize + Send + Default,
        // A bug of rustc, T does not have to be Send actually. See https://github.com/rust-lang/rust/issues/63768
    >(
        &self,
        out: Option<Vec<T>>,
        _sid: MultiplexedStreamID,
    ) -> Result<T, MPCNetError> {
        let bytes: Option<Vec<Vec<u8>>> = out.map(|outs| {
            outs.iter()
                .map(|out| {
                    let mut bytes_out = Vec::new();
                    out.serialize_compressed(&mut bytes_out).unwrap();
                    bytes_out.into()
                })
                .collect()
        });
        if let Some(bytes) = &bytes {
            self.add_comm(bytes.iter().skip(1).map(|b| b.len()).sum::<usize>(), 0);
            Ok(T::deserialize_compressed(&bytes[0][..])?)
        } else {
            Ok(T::default())
        }
    }

    async fn dynamic_worker_receive_or_worker_send_element<
        T: CanonicalDeserialize + CanonicalSerialize + Send + Default,
        // A bug of rustc, T does not have to be Send actually. See https://github.com/rust-lang/rust/issues/63768
    >(
        &self,
        out: Option<Vec<T>>,
        _sender: u32,
        _sid: MultiplexedStreamID,
    ) -> Result<T, MPCNetError> {
        let bytes: Option<Vec<Vec<u8>>> = out.map(|outs| {
            outs.iter()
                .map(|out| {
                    let mut bytes_out = Vec::new();
                    out.serialize_compressed(&mut bytes_out).unwrap();
                    bytes_out.into()
                })
                .collect()
        });
        if let Some(bytes) = &bytes {
            self.add_comm(bytes.iter().skip(1).map(|b| b.len()).sum::<usize>(), 0);
            Ok(T::deserialize_compressed(&bytes[0][..])?)
        } else {
            Ok(T::default())
        }
    }

    /// Everyone sends bytes to the leader, who receives those bytes, runs a computation on them, and
    /// redistributes the resulting bytes.
    ///
    /// The leader's computation is given by a function, `f`
    /// proceeds.
    async fn leader_compute_element<
        T: CanonicalDeserialize + CanonicalSerialize + Send + Clone + Default,
    >(
        &self,
        out: &T,
        sid: MultiplexedStreamID,
        f: impl Fn(Vec<T>) -> Vec<T> + Send,
        for_what: &str,
    ) -> Result<T, MPCNetError> {
        let leader_response = self.worker_send_or_leader_receive_element(out, sid).await?;
        let timer = start_timer!(format!("Leader: Compute element ({})", for_what), self.is_leader());
        let leader_response = leader_response.map(f);
        end_timer!(timer);
        self.worker_receive_or_leader_send_element(leader_response, sid)
            .await
    }
}

impl<N: MPCNet> MPCSerializeNet for N {}
// impl<N: MPCNet> TestMPCSerializeNet for N {}

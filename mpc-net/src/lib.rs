pub mod multi;
pub mod utils;

use async_trait::async_trait;
use auto_impl::auto_impl;
use futures::stream::FuturesOrdered;
use futures::TryStreamExt;
pub use multi::LocalTestNet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use tokio_util::bytes::Bytes;

#[derive(Clone, Debug)]
pub enum MPCNetError {
    Generic(String),
    Protocol { err: String, party: u32 },
    NotConnected,
    BadInput { err: &'static str },
}

impl<T: ToString> From<T> for MPCNetError {
    fn from(e: T) -> Self {
        MPCNetError::Generic(e.to_string())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, Copy)]
pub enum MultiplexedStreamID {
    Zero = 0,
    One = 1,
    Two = 2,
}

#[async_trait]
#[auto_impl(&, &mut, Arc)]
pub trait MPCNet: Send + Sync {
    /// Am I the first party?

    fn is_leader(&self) -> bool {
        self.party_id() == 0
    }
    /// How many parties are there?
    fn n_parties(&self) -> usize;
    /// What is my party number (0 to n-1)?
    fn party_id(&self) -> u32;
    /// Is the network layer initalized?
    fn is_init(&self) -> bool;

    /// Get upload/download in bytes
    fn get_comm(&self) -> (usize, usize);

    fn add_comm(&self, up: usize, down: usize);

    async fn recv_from(&self, id: u32, sid: MultiplexedStreamID) -> Result<Bytes, MPCNetError>;
    async fn send_to(
        &self,
        id: u32,
        bytes: Bytes,
        sid: MultiplexedStreamID,
    ) -> Result<(), MPCNetError>;

    /// All parties send bytes to the leader. The leader receives all the bytes
    async fn worker_send_or_leader_receive(
        &self,
        bytes: &[u8],
        sid: MultiplexedStreamID,
    ) -> Result<Option<Vec<Bytes>>, MPCNetError> {
        let bytes_out = Bytes::copy_from_slice(bytes);
        let own_id = self.party_id();
        let timer = start_timer!(format!("Comm: from {} to leader, {}B", own_id, bytes_out.len()), self.is_leader());

        let r = if self.is_leader() {
            let mut r = FuturesOrdered::new();

            for id in 0..self.n_parties() as u32 {
                let bytes_out: Bytes = bytes_out.clone();
                r.push_back(Box::pin(async move {
                    let bytes_in = if id == own_id {
                        bytes_out
                    } else {
                        self.recv_from(id, sid).await?
                    };

                    Ok::<_, MPCNetError>((id, bytes_in))
                }));
            }

            let mut ret: HashMap<u32, Bytes> = r.try_collect().await?;
            debug_assert_eq!(ret.get(&0).unwrap().clone(), bytes_out);
            // ret.entry(0).or_insert_with(|| bytes_out.clone()); //Why do we need this?

            let mut sorted_ret = Vec::new();
            for x in 0..self.n_parties() {
                sorted_ret.push(ret.remove(&(x as u32)).unwrap());
            }

            Ok(Some(sorted_ret))
        } else {
            self.send_to(0, bytes_out, sid).await?;
            Ok(None)
        };
        end_timer!(timer);
        r
    }

    /// All parties send bytes to someone. The someone receives all the bytes
    async fn dynamic_worker_send_or_leader_receive(
        &self,
        bytes: &[u8],
        receiver: u32,
        sid: MultiplexedStreamID,
    ) -> Result<Option<Vec<Bytes>>, MPCNetError> {
        let bytes_out = Bytes::copy_from_slice(bytes);
        let own_id = self.party_id();
        let timer = start_timer!(format!("Comm: from {} to {}, {}B", own_id, receiver, bytes_out.len()), self.is_leader());

        let r = if receiver == self.party_id() {
            let mut r = FuturesOrdered::new();

            for id in 0..self.n_parties() as u32 {
                let bytes_out: Bytes = bytes_out.clone();
                r.push_back(Box::pin(async move {
                    let bytes_in = if id == own_id {
                        bytes_out
                    } else {
                        self.recv_from(id, sid).await?
                    };

                    Ok::<_, MPCNetError>((id, bytes_in))
                }));
            }

            let mut ret: HashMap<u32, Bytes> = r.try_collect().await?;
            debug_assert_eq!(ret.get(&own_id).unwrap().clone(), bytes_out);
            // ret.entry(0).or_insert_with(|| bytes_out.clone()); //Why do we need this?

            let mut sorted_ret = Vec::new();
            for x in 0..self.n_parties() {
                sorted_ret.push(ret.remove(&(x as u32)).unwrap());
            }

            Ok(Some(sorted_ret))
        } else {
            self.send_to(receiver, bytes_out, sid).await?;
            Ok(None)
        };
        end_timer!(timer);
        r
    }

    /// All parties recv bytes from the leader.
    /// Provide bytes iff you're the leader!
    async fn worker_receive_or_leader_send(
        &self,
        bytes_out: Option<Vec<Bytes>>,
        sid: MultiplexedStreamID,
    ) -> Result<Bytes, MPCNetError> {
        let own_id = self.party_id();

        if let Some(bytes_out) = bytes_out {
            let timer = start_timer!(format!("Comm: from leader to all, {}B", bytes_out.len()), self.is_leader());

            if !self.is_leader() {
                return Err(MPCNetError::BadInput {
                    err: "recv_from_leader called with bytes_out when not leader",
                });
            }

            let m = bytes_out[0].len();

            for id in (0..self.n_parties()).filter(|p| *p != own_id as usize) {
                if bytes_out[id].len() != m {
                    return Err(MPCNetError::Protocol {
                        err: format!("The leader sent wrong number of bytes to Peer {}", id),
                        party: id as u32,
                    });
                }

                self.send_to(id as u32, bytes_out[id].clone(), sid).await?;
            }

            end_timer!(timer);

            Ok(bytes_out[own_id as usize].clone())
        } else {
            if self.is_leader() {
                return Err(MPCNetError::BadInput {
                    err: "recv_from_leader called with no bytes_out when leader",
                });
            }

            self.recv_from(0, sid).await
        }
    }

    /// All parties recv bytes from someone.
    /// Provide bytes iff you're the someone!
    async fn dynamic_worker_receive_or_leader_send(
        &self,
        bytes_out: Option<Vec<Bytes>>,
        sender: u32,
        sid: MultiplexedStreamID,
    ) -> Result<Bytes, MPCNetError> {
        let own_id = self.party_id();

        if let Some(bytes_out) = bytes_out {

            let timer = start_timer!(format!("Comm: from {} to all, {}B", own_id, bytes_out.len()), self.is_leader());

            if !own_id == sender {
                return Err(MPCNetError::BadInput {
                    err: "recv_from_leader called with bytes_out when not leader",
                });
            }

            let m = bytes_out[0].len();

            for id in (0..self.n_parties()).filter(|p| *p != own_id as usize) {
                if bytes_out[id].len() != m {
                    return Err(MPCNetError::Protocol {
                        err: format!("The leader sent wrong number of bytes to Peer {}", id),
                        party: id as u32,
                    });
                }

                self.send_to(id as u32, bytes_out[id].clone(), sid).await?;
            }

            end_timer!(timer);

            Ok(bytes_out[own_id as usize].clone())
        } else {
            if own_id == sender{
                return Err(MPCNetError::BadInput {
                    err: "recv_from_leader called with no bytes_out when leader",
                });
            }

            self.recv_from(sender, sid).await
        }
    }

    /// Everyone sends bytes to the leader, who receives those bytes, runs a computation on them, and
    /// redistributes the resulting bytes.
    ///
    /// The leader's computation is given by a function, `f`
    /// proceeds.
    async fn leader_compute(
        &self,
        bytes: &[u8],
        sid: MultiplexedStreamID,
        f: impl Fn(Vec<Bytes>) -> Vec<Bytes> + Send,
    ) -> Result<Bytes, MPCNetError> {
        let leader_response = self.worker_send_or_leader_receive(bytes, sid).await?.map(f);
        self.worker_receive_or_leader_send(leader_response, sid)
            .await
    }
}

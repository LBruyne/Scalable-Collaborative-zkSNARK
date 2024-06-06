use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::fs::File;
use std::future::Future;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::{MPCNetError, MultiplexedStreamID};
use async_smux::{MuxBuilder, MuxStream};
use async_trait::async_trait;
use futures::stream::{FuturesOrdered, FuturesUnordered};
use futures::{SinkExt, StreamExt, TryStreamExt};
use log::trace;
use parking_lot::Mutex;
use tokio::sync::Mutex as TokioMutex;
use tokio_util::bytes::Bytes;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use super::MPCNet;

pub type WrappedStream<T> = Framed<T, LengthDelimitedCodec>;

pub fn wrap_stream<T: AsyncRead + AsyncWrite>(stream: T) -> Framed<T, LengthDelimitedCodec> {
    LengthDelimitedCodec::builder()
        .big_endian()
        .length_field_type::<u32>()
        .new_framed(stream)
}

pub struct Peer<IO: AsyncRead + AsyncWrite + Unpin> {
    pub id: u32,
    pub listen_addr: SocketAddr,
    pub streams: Option<Vec<TokioMutex<WrappedMuxStream<IO>>>>,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Debug for Peer<IO> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut f = f.debug_struct("Peer");
        f.field("id", &self.id);
        f.field("listen_addr", &self.listen_addr);
        f.field("streams", &self.streams.is_some());
        f.finish()
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Clone for Peer<IO> {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            listen_addr: self.listen_addr,
            streams: None,
        }
    }
}

pub type WrappedMuxStream<T> = Framed<MuxStream<T>, LengthDelimitedCodec>;
pub const MULTIPLEXED_STREAMS: usize = 3;

/// Should be called immediately after making a connection to a peer.
pub async fn multiplex_stream<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    channels: usize,
    is_server: bool,
    stream: T,
) -> Result<Vec<TokioMutex<WrappedMuxStream<T>>>, MPCNetError> {
    if is_server {
        let (_connector, mut acceptor, worker) =
            MuxBuilder::server().with_connection(stream).build();
        tokio::spawn(worker);
        let mut ret = Vec::new();
        for _ in 0..channels {
            ret.push(TokioMutex::new(wrap_stream(
                acceptor.accept().await.ok_or_else(|| {
                    MPCNetError::Generic("Error accepting connection".to_string())
                })?,
            )));
        }

        Ok(ret)
    } else {
        let (connector, _acceptor, worker) = MuxBuilder::client().with_connection(stream).build();
        tokio::spawn(worker);
        let mut ret = Vec::new();
        for _ in 0..channels {
            ret.push(TokioMutex::new(wrap_stream(connector.connect()?)));
        }

        Ok(ret)
    }
}

#[derive(Default, Debug)]
pub struct MPCNetConnection<IO: AsyncRead + AsyncWrite + Unpin> {
    pub id: u32,
    pub listener: Option<TcpListener>,
    pub peers: HashMap<u32, Peer<IO>>,
    pub n_parties: usize,
    pub upload: AtomicUsize,
    pub download: AtomicUsize,
}

impl MPCNetConnection<TcpStream> {
    pub fn init_from_path(path: &PathBuf, id: u32) -> Self {
        let mut this = MPCNetConnection {
            id: 0 as u32,
            listener: None,
            peers: Default::default(),
            n_parties: 0,
            upload: AtomicUsize::new(0),
            download: AtomicUsize::new(0),
        };
        let f = BufReader::new(File::open(path).expect("host configuration path"));
        let mut peer_id = 0;
        for line in f.lines() {
            let line = line.unwrap();
            let trimmed = line.trim();
            if trimmed.len() > 0 {
                let addr: SocketAddr = trimmed
                    .parse()
                    .unwrap_or_else(|e| panic!("bad socket address: {}:\n{}", trimmed, e));
                let peer = Peer {
                    id: peer_id,
                    listen_addr: addr,
                    streams: None,
                };
                this.peers.insert(peer_id, peer);
                peer_id += 1;
            }
        }
        assert!(id < this.peers.len() as u32);
        this.id = id;
        this.n_parties = this.peers.len();
        this
    }

    pub async fn listen(&mut self) -> Result<(), MPCNetError> {
        let listen_addr = self.peers.get(&self.id).unwrap().listen_addr;
        trace!("Listening on {listen_addr}");
        self.listener = Some(
            TcpListener::bind(listen_addr)
                .await
                .unwrap(),
        );
        Ok(())
    }

    pub async fn connect_to_all(&mut self) -> Result<(), MPCNetError> {
        let n_minus_1 = self.n_parties() - 1;
        let my_id = self.id;

        let peer_addrs = self
            .peers
            .iter()
            .map(|p| (*p.0, p.1.listen_addr))
            .collect::<HashMap<_, _>>();

        let listener = self.listener.take().expect("TcpListener is None");
        let new_peers = Arc::new(Mutex::new(self.peers.clone()));
        let new_peers_server = new_peers.clone();
        let new_peers_client = new_peers.clone();

        // my_id = 0, n_minus_1 = 2
        // outbound_connections_i_will_make = 2
        // my_id = 1, n_minus_1 = 2
        // outbound_connections_i_will_make = 1
        // my_id = 2, n_minus_1 = 2
        // outbound_connections_i_will_make = 0
        let outbound_connections_i_will_make = n_minus_1 - (my_id as usize);
        let inbound_connections_i_will_make = my_id as usize;

        let server_task = async move {
            for _ in 0..inbound_connections_i_will_make {
                let (mut stream, _peer_addr) = listener.accept().await.map_err(|err| {
                    MPCNetError::Generic(format!("Error accepting connection: {err:?}"))
                })?;

                let peer_id = stream.read_u32().await?;
                // Now, multiplex the stream
                let muxed = multiplex_stream(MULTIPLEXED_STREAMS, true, stream).await?;
                new_peers_server.lock().get_mut(&peer_id).unwrap().streams = Some(muxed);
                trace!("{my_id} connected to peer {peer_id}")
            }

            Ok::<_, MPCNetError>(())
        };

        let client_task = async move {
            // Wait some time for the server tasks to boot up
            tokio::time::sleep(Duration::from_millis(200)).await;
            // Listeners are all active, now, connect us to n-1 peers
            for conns_made in 0..outbound_connections_i_will_make {
                // If I am 0, I will connect to 1 and 2
                // If I am 1, I will connect to 2
                // If I am 2, I will connect to no one (server will make the connections)
                let next_peer_to_connect_to = my_id + conns_made as u32 + 1;
                let peer_listen_addr = peer_addrs.get(&next_peer_to_connect_to).unwrap();
                let mut stream = {
                    let mut res = Err(io::Error::new(io::ErrorKind::Other, "Initial error"));
                    for _ in 0..30 {
                        res = TcpStream::connect(peer_listen_addr).await;
                        if res.is_ok() {
                            // trace!("Connected to peer {next_peer_to_connect_to}");
                            break;
                        }
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    res.map_err(|err| {
                        MPCNetError::Generic(format!(
                            "Error connecting to peer {next_peer_to_connect_to}: {err:?}"
                        ))
                    })
                }?;
                stream.write_u32(my_id).await.unwrap();

                let muxed = multiplex_stream(MULTIPLEXED_STREAMS, false, stream).await?;
                new_peers_client
                    .lock()
                    .get_mut(&next_peer_to_connect_to)
                    .unwrap()
                    .streams = Some(muxed);
                trace!("{my_id} connected to peer {next_peer_to_connect_to}")
            }

            Ok::<_, MPCNetError>(())
        };

        trace!("Awaiting on client and server task to finish");

        tokio::try_join!(server_task, client_task)?;
        self.peers = Arc::try_unwrap(new_peers).unwrap().into_inner();

        trace!("All connected");

        // Every party will use this channel for genesis
        let genesis_round_channel = MultiplexedStreamID::Zero;

        // Do a round with the leader, to be sure everyone is ready
        let from_all = self
            .worker_send_or_leader_receive(&[self.id as u8] as &[u8], genesis_round_channel)
            .await?;
        self.worker_receive_or_leader_send(from_all, genesis_round_channel)
            .await?;

        for peer in &self.peers {
            if peer.0 == &self.id {
                continue;
            }

            if peer.1.streams.is_none() {
                return Err(MPCNetError::Generic(format!(
                    "Peer {} has no stream",
                    peer.0
                )));
            }
        }

        trace!("Done with p2p connection");
        Ok(())
    }
}

pub struct LocalTestNet {
    nodes: HashMap<usize, MPCNetConnection<TcpStream>>,
}

impl LocalTestNet {
    pub async fn new_local_testnet(n_parties: usize) -> Result<Self, MPCNetError> {
        // Step 1: Generate all the Listeners for each node
        let mut listeners = HashMap::new();
        let mut listen_addrs = HashMap::new();
        for party_id in 0..n_parties {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            listen_addrs.insert(party_id, listener.local_addr()?);
            listeners.insert(party_id, listener);
        }

        // Step 2: populate the nodes with peer metadata (do NOT init the connections yet)
        let mut nodes = HashMap::new();
        for (my_party_id, my_listener) in listeners.into_iter() {
            let mut connections = MPCNetConnection {
                id: my_party_id as u32,
                listener: Some(my_listener),
                peers: Default::default(),
                n_parties,
                upload: AtomicUsize::new(0),
                download: AtomicUsize::new(0),
            };
            for peer_id in 0..n_parties {
                // NOTE: this is the listen addr
                let peer_addr = listen_addrs.get(&peer_id).copied().unwrap();
                connections.peers.insert(
                    peer_id as u32,
                    Peer {
                        id: peer_id as u32,
                        listen_addr: peer_addr,
                        streams: None,
                    },
                );
            }

            nodes.insert(my_party_id, connections);
        }

        // Step 3: Connect peers to each other
        trace!("Now running init");
        let futures = FuturesUnordered::new();
        for (peer_id, mut connections) in nodes.into_iter() {
            futures.push(Box::pin(async move {
                connections.connect_to_all().await?;
                Ok::<_, MPCNetError>((peer_id, connections))
            }));
        }

        let nodes = futures.try_collect().await?;

        Ok(Self { nodes })
    }

    /// For each node, run a function (a Future) provided by the parameter that accepts the node's Connection.
    /// Then, run all these futures in a FuturesOrdered.
    ///
    /// The provided `user_data` of type U is then given to each of these futures, by cloning it.
    /// So if you have a struct that you want to pass to each of these futures, you can do that.
    pub async fn simulate_network_round<
        F: Future<Output = K> + Send,
        K: Send + Sync + 'static,
        U: Clone + Send + Sync + 'static,
    >(
        self,
        user_data: U,
        f: impl Fn(MPCNetConnection<TcpStream>, U) -> F + Send + Sync + Clone + 'static,
    ) -> Vec<K> {
        let mut futures = FuturesOrdered::new();
        let mut sorted_nodes = self.nodes.into_iter().collect::<Vec<_>>();
        sorted_nodes.sort_by(|a, b| a.0.cmp(&b.0));
        for (_, connections) in sorted_nodes {
            let next_f = f.clone();
            let next_user_data = user_data.clone();
            futures.push_back(Box::pin(async move {
                let task = async move { next_f(connections, next_user_data).await };
                let handle = tokio::task::spawn(task);
                handle.await.unwrap()
            }));
        }
        futures.collect().await
    }

    /// Get the connection for a given party ID
    pub fn get_connection(&self, party_id: usize) -> &MPCNetConnection<TcpStream> {
        self.nodes.get(&party_id).unwrap()
    }

    pub fn get_leader(&self) -> &MPCNetConnection<TcpStream> {
        self.get_connection(0)
    }
}

#[async_trait]
impl<IO: AsyncRead + AsyncWrite + Unpin + Send> MPCNet for MPCNetConnection<IO> {
    fn n_parties(&self) -> usize {
        self.n_parties
    }

    fn party_id(&self) -> u32 {
        self.id
    }

    fn is_init(&self) -> bool {
        self.peers.iter().all(|r| r.1.streams.is_some())
    }

    fn get_comm(&self) -> (usize, usize) {
        (
            self.upload.load(Ordering::Relaxed),
            self.download.load(Ordering::Relaxed),
        )
    }
    fn add_comm(&self, up: usize, down: usize) {
        self.upload.fetch_add(up, Ordering::Relaxed);
        self.download.fetch_add(down, Ordering::Relaxed);
    }

    async fn recv_from(&self, id: u32, sid: MultiplexedStreamID) -> Result<Bytes, MPCNetError> {
        let peer = self
            .peers
            .get(&id)
            .ok_or_else(|| MPCNetError::Generic(format!("Peer {} not found", id)))?;
        let result = recv_stream(peer.streams.as_ref(), sid).await;
        if let Ok(bytes) = &result {
            self.download.fetch_add(bytes.len(), Ordering::Relaxed);
        }
        result
    }

    async fn send_to(
        &self,
        id: u32,
        bytes: Bytes,
        sid: MultiplexedStreamID,
    ) -> Result<(), MPCNetError> {
        let peer = self
            .peers
            .get(&id)
            .ok_or_else(|| MPCNetError::Generic(format!("Peer {} not found", id)))?;
        let len = bytes.len();
        let result = send_stream(peer.streams.as_ref(), bytes, sid).await;
        if let Ok(_) = &result {
            self.upload.fetch_add(len, Ordering::Relaxed);
        }
        result
    }
}

async fn send_stream<T: AsyncRead + AsyncWrite + Unpin>(
    stream: Option<&Vec<TokioMutex<WrappedStream<T>>>>,
    bytes: Bytes,
    sid: MultiplexedStreamID,
) -> Result<(), MPCNetError> {
    if let Some(stream) = stream.and_then(|r| r.get(sid as usize)) {
        Ok(stream.lock().await.send(bytes).await?)
    } else {
        Err(MPCNetError::Generic("Stream is None".to_string()))
    }
}

async fn recv_stream<T: AsyncRead + AsyncWrite + Unpin>(
    stream: Option<&Vec<TokioMutex<WrappedStream<T>>>>,
    sid: MultiplexedStreamID,
) -> Result<Bytes, MPCNetError> {
    if let Some(stream) = stream.and_then(|r| r.get(sid as usize)) {
        Ok(stream
            .lock()
            .await
            .next()
            .await
            .ok_or_else(|| MPCNetError::Generic("Stream died".to_string()))??
            .freeze())
    } else {
        Err(MPCNetError::Generic("Stream is None".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use crate::multi::{recv_stream, send_stream};
    use crate::{LocalTestNet, MultiplexedStreamID};
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_multiplexing() {
        const N_PARTIES: usize = 4;
        let testnet = LocalTestNet::new_local_testnet(N_PARTIES).await.unwrap();
        let expected_sum = (0..4).sum::<u32>();

        testnet
            .simulate_network_round((), move |conn, _| async move {
                let sids = [
                    MultiplexedStreamID::Zero,
                    MultiplexedStreamID::One,
                    MultiplexedStreamID::Two,
                ];
                // Broadcast our ID to everyone
                let my_id = conn.id;
                for peer in &mut conn.peers.values() {
                    if peer.id == my_id {
                        continue;
                    }
                    for sid in sids {
                        send_stream(peer.streams.as_ref(), vec![my_id as u8].into(), sid)
                            .await
                            .unwrap();
                    }
                }

                // Receive everyone else's ID
                let mut ids = HashMap::<_, Vec<u32>>::new();
                for peer in &mut conn.peers.values() {
                    if peer.id == my_id {
                        continue;
                    }
                    for sid in sids {
                        let recv_bytes = recv_stream(peer.streams.as_ref(), sid).await.unwrap();
                        let decoded = recv_bytes[0] as u32;
                        ids.entry(sid).or_default().push(decoded);
                    }
                }

                for (_sid, ids) in ids {
                    assert_eq!(expected_sum, ids.iter().sum::<u32>() + my_id);
                }
            })
            .await;
    }
}

use rug::Integer;
use actix::prelude::*;
use rand::{self, Rng};

use peer::*;

pub struct Network {
    pub peers: Vec<Addr<Peer>>
}

/// A peer connected to the network
#[derive(Message)]
pub struct Connect {
    pub id: PeerId,
    pub addr: Addr<Peer>,
}

/// A peer sent its commitment to the randomness
#[derive(Message, Debug, Copy, Clone)]
pub struct Commitment {
    pub id_from: PeerId,
    pub value: u64,
}

/// A peer calculated VDF and sent it result and seed
#[derive(Message, Debug, Clone)]
pub struct VdfResult {
    pub id_from: PeerId,

    pub seed: Integer,
    pub result: Integer,
}

/// Make actor from `Network`
impl Actor for Network {
    type Context = Context<Self>;
}

impl Network {
    pub fn broadcast_commitment(&self, commitment: Commitment) {
        let mut peers = self.peers.clone();

        // Shuffle peers to simulate network propagation delay and non-determinism.
        // Algorithm should be robust against difference in time of arrival of messages
        rand::thread_rng().shuffle(peers.as_mut());

        // Broadcast message among peers
        for peer in peers.iter() {
            peer.do_send(commitment)
        }
    }

    pub fn broadcast_vdf_result(&self, result: VdfResult) {
        let mut peers = self.peers.clone();

        // Shuffle peers to simulate network propagation delay and non-determinism.
        // Algorithm should be robust against difference in time of arrival of messages
        rand::thread_rng().shuffle(peers.as_mut());

        // Broadcast message among peers
        for peer in peers.iter() {
            peer.do_send(result.clone())
        }
    }
}

impl Default for Network {
    fn default() -> Self {
        Network { peers: vec![] }
    }
}

impl Handler<Connect> for Network {
    type Result = ();

    fn handle(&mut self, msg: Connect, _: &mut Context<Self>) {
        println!("[network] Peer {:?} joined the network", msg.id);

        self.peers.push(msg.addr);
    }
}

impl Handler<Commitment> for Network {
    type Result = ();

    fn handle(&mut self, msg: Commitment, _: &mut Context<Self>) {
        self.broadcast_commitment(msg);
    }
}

impl Handler<VdfResult> for Network {
    type Result = ();

    fn handle(&mut self, msg: VdfResult, _: &mut Context<Self>) {
        self.broadcast_vdf_result(msg);
    }
}
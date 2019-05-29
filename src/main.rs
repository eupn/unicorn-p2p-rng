mod network;
mod peer;

use actix::prelude::*;

/// Number of peers that want to agree on a single verifiable random number
const NUM_PEERS: u32 = 6;

/// Minimum delay (sec.) before peer send its commitment
pub const COMMITMENTS_DELAY_MIN: u64 = 1;

/// Timeout (sec.) in which peers are waiting for other peer's commitments
pub const COMMITMENTS_ROUND_TIMEOUT: u64 = NUM_PEERS as u64 * 1;

/// Timeout (sec.) in which peers are waiting for other peer's VDF calculation results
/// after they calculated and sent its own VDF
pub const VDF_GATHERING_TIMEOUT: u64 = NUM_PEERS as u64 * 1;

pub const VDF_PARAMS: u16 = 1024;

/// Difficulty of the VDF calculation.
/// VDF delay for the most CPU-powerful peer should be at least
/// two times more than timeout of commitments gathering
pub const VDF_DIFFICULTY: u64 = 100_000;

fn main() {
    actix::System::run(|| {
        // Create the network relay actor
        let network = network::Network::default().start();

        for id in 0u32..NUM_PEERS {
            let peer = peer::Peer::new(id, NUM_PEERS, network.clone());

            Arbiter::start(move |_| peer);
        }
    });
}

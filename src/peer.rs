use actix::prelude::*;

use super::{
    COMMITMENTS_DELAY_MIN, COMMITMENTS_ROUND_TIMEOUT, VDF_DIFFICULTY, VDF_GATHERING_TIMEOUT,
    VDF_PARAMS,
};
use crate::network::*;

use rand::{self, Rng};

use std::collections::HashMap;
use std::time::Duration;

use vdf::*;

/// Defines possible states of the peer.
#[derive(Debug, Copy, Clone)]
pub enum PeerState {
    Idle,
    Connected,
    Commit,
    DoingVdf,
    VerifyingVdf,
}

pub type PeerId = u32;

/// Describes single independent peer in the network.
#[derive(Debug)]
pub struct Peer {
    /// ID of this peer.
    pub id: PeerId,

    /// Total number of peers known.
    pub num_peers: u32,

    /// Peer's address in the network.
    pub net_addr: Addr<Network>,

    /// Current state of the peer.
    pub state: PeerState,

    /// Collection of the commitments to the seed from the peers.
    pub commitments: HashMap<PeerId, Commitment>,

    /// Seed for the VDF in current round.
    pub seed: Option<Vec<u8>>,

    /// Collection of VDF results received from the peers.
    pub vdf_results: HashMap<PeerId, VdfResult>,
}

impl Peer {
    pub fn new(id: u32, num_peers: u32, net_addr: Addr<Network>) -> Self {
        Peer {
            id,
            num_peers,
            net_addr,

            state: PeerState::Idle,
            commitments: HashMap::new(),
            seed: None,
            vdf_results: HashMap::new(),
        }
    }

    fn create_commitment_after_delay(&mut self, ctx: &mut actix::Context<Self>) {
        println!(
            "[commitment round] Peer #{} is creating a commitment",
            self.id
        );

        let delay = COMMITMENTS_DELAY_MIN + rand::thread_rng().gen::<u64>() % 5;
        ctx.run_later(Duration::new(delay, 0), |act, _| {
            let mut array = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut array);

            let commitment = Commitment {
                id_from: act.id,
                value: array,
            };

            act.net_addr.do_send(commitment);
            act.state = PeerState::Commit;
        });

        ctx.run_later(Duration::new(COMMITMENTS_ROUND_TIMEOUT, 0), |act, ctx| {
            act.commitments_round_finished(ctx)
        });
    }

    fn commitments_round_finished(&mut self, ctx: &mut Context<Self>) {
        // Commitment round finished but actor wasn't commit,
        // something went wrong and actor is aboring
        match self.state {
            PeerState::Commit => {}

            _ => {
                println!("[commitment round] Peer {} wasn't commit", self.id);

                ctx.stop();
                return;
            }
        };

        // If we collected more than 2/3 of commitments we can proceed to
        // combining them into a seed
        if self.commitments.len() as f32 >= self.num_peers as f32 * (2f32 / 3f32) {
            // Sort commitments by peer ID to protect from different result per peer due to
            // different time of arrival of particular commitment to the particular peer.
            let mut commitments = self
                .commitments
                .values()
                .into_iter()
                .map(|c| *c)
                .collect::<Vec<_>>();
            commitments.sort_unstable_by_key(|k| k.id_from);

            println!(
                "[commitment round] Peer #{} is creating seed from commitments: {:?}",
                self.id, commitments
            );

            // Create a seed by appending commitments
            let seed = commitments
                .into_iter()
                .map(|c| c.value.to_vec())
                .flatten()
                .collect::<Vec<_>>();
            let seed = hash(&seed);

            self.seed = Some(seed.clone());

            println!(
                "[commitment round] #{}: seed created: {}",
                self.id,
                hex::encode(seed)
            );

            self.calculate_vdf(ctx);
        } else {
            println!(
                "[commitment round] #{}: not enough commitments collected, restarting",
                self.id
            );
            self.create_commitment_after_delay(ctx);
        }
    }

    fn calculate_vdf(&mut self, ctx: &mut Context<Self>) {
        if let None = self.seed {
            println!("[error] Peer #{} didn't generated a seed", self.id);
            return;
        }

        let seed = self.seed.clone().unwrap();

        println!("[vdf round] Peer #{} is calculating VDF...", self.id);

        self.state = PeerState::DoingVdf;
        let witness = vdf::PietrzakVDFParams(VDF_PARAMS)
            .new()
            .solve(&seed, VDF_DIFFICULTY)
            .unwrap();

        let vdf_result = VdfResult {
            id_from: self.id,
            seed,
            result: witness,
        };

        //println!("[vdf round] Peer #{} is calculated VDF and sent its result", self.id);
        self.net_addr.do_send(vdf_result);

        ctx.run_later(Duration::new(VDF_GATHERING_TIMEOUT, 0), |act, _| {
            act.state = PeerState::VerifyingVdf;

            println!("[vdf round] Peer #{} is verifying {} VDF results", act.id, act.vdf_results.len());

            // Verify all VDF results that we collected
            let mut num_valid = 0;
            if let Some(seed) = act.seed.clone() {
                for vdf_result in act.vdf_results.values() {
                    // Reject results with different seed
                    if vdf_result.seed != seed {
                        continue
                    }

                    let verification = vdf::PietrzakVDFParams(VDF_PARAMS).new().verify(&seed, VDF_DIFFICULTY, &vdf_result.result);
                    if verification.is_ok() {
                        num_valid += 1;
                    }
                }
            }

            // If more than 2/3 of valid results collected
            if num_valid as f32 >= act.num_peers as f32 * (2f32 / 3f32) {
                // New random is the any of the valid VDF results (they're supposed to be the same)
                let new_random_number = &act.vdf_results
                    .values().nth(0).clone().unwrap()
                    .result;
                let new_random_number = hash(&new_random_number);

                println!("[SUCCESS] Peer #{} thinks that more than 2/3 of peers agreed on: {} as next random number", act.id, hex::encode(new_random_number));
            } else {
                println!("[FAILURE] Peer #{} thinks that there's not enough evidence to think that any valid number are possible to obtain.", act.id);
            }
        });
    }
}

/// Make actor from `Peer`
impl Actor for Peer {
    type Context = actix::Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        // register self in network. `AsyncContext::wait` register
        // future within context, but context waits until this future resolves
        // before processing any other events.
        self.net_addr
            .send(Connect {
                addr: ctx.address(),
                id: self.id,
            })
            .into_actor(self)
            .then(|_, act, ctx| {
                act.state = PeerState::Connected;

                act.create_commitment_after_delay(ctx);

                actix::fut::ok(())
            })
            .wait(ctx);
    }

    fn stopping(&mut self, _: &mut Self::Context) -> Running {
        Running::Stop
    }
}

impl Handler<Commitment> for Peer {
    type Result = ();

    fn handle(&mut self, msg: Commitment, _: &mut Context<Self>) {
        // Save commitment if it wasn't already received
        if !self.commitments.contains_key(&msg.id_from) {
            let id_from = msg.id_from;
            self.commitments.insert(msg.id_from, msg);

            println!(
                "[commitment round] Peer #{} saved commitment {} from #{}",
                self.id,
                hex::encode(msg.value),
                id_from
            );
        }
    }
}

impl Handler<VdfResult> for Peer {
    type Result = ();

    fn handle(&mut self, msg: VdfResult, _: &mut Context<Self>) {
        if !self.vdf_results.contains_key(&msg.id_from) {
            let id_from = msg.id_from;
            self.vdf_results.insert(msg.id_from, msg);

            println!(
                "[vdf round] Peer #{} saved VDF result from #{}",
                self.id, id_from
            );
        }
    }
}

fn hash(bytes: &[u8]) -> Vec<u8> {
    use sha2::Digest;

    let mut sha = sha2::Sha256::new();
    sha.input(bytes);
    sha.result().to_vec()
}

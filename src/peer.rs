use rug::Integer;
use actix::prelude::*;

use super::{COMMITMENTS_DELAY_MIN, COMMITMENTS_ROUND_TIMEOUT, VDF_NUM_STEPS, VDF_GATHERING_TIMEOUT};
use network::*;

use rand::{self, Rng};
use std::time::{Duration};

// Import MiMC-based verifiable delay function
use vdf::vdf_mimc;

/// Possible states of the peer.
#[derive(Copy, Clone)]
pub enum PeerState {
    Idle,
    Connected,
    Commit,
    DoingVdf,
    VerifyingVdf
}

pub type PeerId = u32;

pub struct Peer {
    pub id: PeerId,
    pub num_peers: u32,
    pub net_addr: Addr<Network>,
    pub state: PeerState,

    pub commitments: Vec<Commitment>,
    pub seed: Option<Integer>,
    pub vdf_results: Vec<VdfResult>,
}

impl Peer {
    pub fn new(id: u32, num_peers: u32, net_addr: Addr<Network>) -> Self {
        Peer {
            id, num_peers, net_addr,

            state: PeerState::Idle,
            commitments: vec![],
            seed: None,
            vdf_results: vec![]
        }
    }

    fn create_commitment_after_delay(&mut self, ctx: &mut actix::Context<Self>) {
        println!("[commitment round] Peer #{} is creating a commitment", self.id);

        let delay = COMMITMENTS_DELAY_MIN + rand::thread_rng().gen::<u64>() % 5;
        ctx.run_later(Duration::new(delay, 0), |act, _| {
            let commitment = Commitment {
                id_from: act.id,
                value: rand::thread_rng().gen::<u64>()
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
            PeerState::Commit => {},

            _ => {
                println!("[commitment round] Peer {} wasn't commit", self.id);

                ctx.stop();
                return
            }
        };

        // If we collected more than 2/3 of commitments we can proceed to
        // combining them into a seed
        if self.commitments.len() as f32 >= self.num_peers as f32 * (2f32 / 3f32) {
            let mut seed = 0;
            for commitment in self.commitments.iter() {
                seed ^= commitment.value;
            }

            let seed = Integer::from(seed);
            self.seed = Some(seed.clone());

            println!("[commitment round] #{}: seed created: {}", self.id, seed);

            self.calculate_vdf(ctx);
        } else {
            println!("[commitment round] #{}: not enough commitments collected, restarting", self.id);
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
        let witness = vdf_mimc::eval(&seed, VDF_NUM_STEPS);

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

            // Verify all VDF result that we collected
            let mut num_valid = 0;
            if let Some(seed) = act.seed.clone() {
                for vdf_result in act.vdf_results.iter() {
                    // Reject results with different seed
                    if vdf_result.seed != seed {
                        continue
                    }

                    let is_valid = vdf_mimc::verify(&seed, VDF_NUM_STEPS, &vdf_result.result);
                    if is_valid {
                        num_valid += 1;
                    }
                }
            }

            // If more than 2/3 of valid results collected
            if num_valid as f32 >= act.num_peers as f32 * (2f32 / 3f32) {
                println!("[SUCCESS] Peer #{} thinks that more than 2/3 of peers agreed on: {} as next random number", act.id, act.vdf_results[0].result);
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
        println!("[commitment round] Peer #{} received commitment {} from #{}", self.id, msg.value, msg.id_from);
        self.commitments.push(msg);
    }
}

impl Handler<VdfResult> for Peer {
    type Result = ();

    fn handle(&mut self, msg: VdfResult, _: &mut Context<Self>) {
        println!("[vdf round] Peer #{} received VDF result from #{}", self.id, msg.id_from);
        self.vdf_results.push(msg);
    }
}
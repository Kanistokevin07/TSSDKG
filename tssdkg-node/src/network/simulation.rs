use crate::network::node::Node;
use crate::network::message::{Message, Payload};
use crate::core::feldman_vss::tamper_share;
use crate::security::resharing::ResharingEngine;
use crate::core::feldman_vss::generate_verified_shares;
use crate::ml::export::export_metrics;
use rand::Rng;
use crate::security::epoch::EpochManager;
use std::collections::HashSet;

pub struct Simulation {
    pub nodes: Vec<Node>,
    pub epoch_mgr: EpochManager,
    pub threshold: usize,
}

impl Simulation {
    pub fn new(num_nodes: usize, threshold: usize) -> Self {
        let mut nodes = Vec::new();

        for i in 0..num_nodes {
            nodes.push(Node::new(i as u32 + 1, threshold, 100 + i as i64));
        }

        // initialize peers
        let node_ids: Vec<u32> = nodes.iter().map(|n| n.id).collect();

        for i in 0..num_nodes {
            let my_id = nodes[i].id;

            for &peer_id in &node_ids {
                if peer_id != my_id {
                    nodes[i]
                        .peers
                        .insert(peer_id, crate::security::reputation::PeerState::new(peer_id));
                }
            }
            
        }
        Self {
            nodes,
            epoch_mgr: EpochManager::new(),
            threshold,
        }
        
    }
    pub fn pick_attackers(&self, k: usize) -> Vec<u32> {
        let mut rng = rand::thread_rng();
        let mut attackers = Vec::new();

        while attackers.len() < k {
            let id = rng.gen_range(1..=self.nodes.len() as u32);
            if !attackers.contains(&id) {
                attackers.push(id);
            }
        }

        attackers
    }

    /// Broadcast message to all nodes except sender
    pub fn broadcast(&mut self, sender_id: u32, msg: Message) {
        for node in self.nodes.iter_mut() {
            if node.id != sender_id {
                node.handle_message(msg.clone());
            }
        }
    }

    pub fn simulate_honest_traffic(&mut self) {
        println!("\n Simulating honest traffic...\n");

        let shares = generate_verified_shares(
            12345,
            self.nodes.len(),
            3,
            crate::core::feldman_vss::Q_ORDER,
            crate::core::feldman_vss::P_MODULUS,
        );

        for i in 0..self.nodes.len() {
            let sender_id = self.nodes[i].id;

            for j in 0..self.nodes.len() {
                if i != j {
                    let mut all_shares = Vec::new();

                    for _ in 0..self.nodes.len() {
                        all_shares.push(generate_verified_shares(
                            12345,
                            self.nodes.len(),
                            3,
                            crate::core::feldman_vss::Q_ORDER,
                            crate::core::feldman_vss::P_MODULUS,
                        ));
                    }
                    let good_share = shares[(i) as usize].clone();

                    let msg = Message {
                        from: sender_id,
                        epoch: 0,
                        payload: Payload::Share(good_share),
                    };

                    self.nodes[j].handle_message(msg);
                }
            }
        }
    }

    /// Simulate malicious node sending bad shares
    pub fn simulate_attack(&mut self, attacker_id: u32) {
        println!("\n Node {} launching attack...\n", attacker_id);

        // Generate REAL valid shares first
        let shares = generate_verified_shares(
            12345,
            self.nodes.len(),
            3,
            crate::core::feldman_vss::Q_ORDER,
            crate::core::feldman_vss::P_MODULUS,
        );

        for node in self.nodes.iter_mut() {
            if node.id != attacker_id {
                // 🔥 Tamper one share
                let bad_share = tamper_share(&shares[(node.id - 1) as usize]);

                let msg = Message {
                    from: attacker_id,
                    epoch: 0,
                    payload: Payload::Share(bad_share),
                };

                node.handle_message(msg);
            }
        }
        
    }

    pub fn run_round(&mut self, attacker_id: u32) {

        // Step 1: honest traffic (baseline)
        self.simulate_honest_traffic();

        // Step 2: attack traffic
        let attackers = self.pick_attackers(2); // 2 attackers

        for attacker in attackers {
            for _ in 0..5 {
                self.simulate_attack(attacker);
            }
        }
    

        // Step 3: each node decides
        println!("\n Evaluating network...\n");

        for node in self.nodes.iter_mut() {
            node.evaluate_network();
        }
        // ------------------------
// GLOBAL AGGREGATION LAYER
// ------------------------

        let mut malicious_votes: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();

        // Count how many nodes flagged each peer
        for node in &self.nodes {
            for (peer_id, peer) in &node.peers {
                if peer.is_malicious() {
                    *malicious_votes.entry(*peer_id).or_insert(0) += 1;
                }
            }
        }

        let mut globally_malicious = std::collections::HashSet::new();

        for (peer_id, votes) in malicious_votes {
            if votes >= self.threshold {
                println!("🌍 Global consensus: Node {} is malicious ({} votes)", peer_id, votes);
                globally_malicious.insert(peer_id);
            }
        }
        let mut malicious_peers = HashSet::new();

        for node in &self.nodes {
            for (peer_id, peer) in &node.peers {
                if peer.is_malicious() {
                    malicious_peers.insert(*peer_id);
                }
            }
        }

        let resharing_needed = !globally_malicious.is_empty();

        if resharing_needed {
            println!("\n🌐 Global resharing triggered...\n");

            // ✅ Step 1: compute epoch ONCE
            let new_epoch = self.epoch_mgr.next();

            println!("\n🌐 Global resharing triggered → epoch {}\n", new_epoch);

            // ✅ Step 2: resharing
            for node in self.nodes.iter_mut() {
                let (new_share, _) =
                    ResharingEngine::trigger(node.share, node.threshold, &node.epoch_mgr);

                node.share = new_share;
                node.needs_resharing = false;
                node.last_reshared_epoch = new_epoch;

                println!("🔁 Node {} reshared → epoch {}", node.id, new_epoch);
            }

            // ✅ Step 3: reset
            for node in self.nodes.iter_mut() {
                node.reset_epoch_state();
            }
        }

        

        export_metrics(&self.nodes);
        std::process::Command::new("python")
        .arg("src/ml/analyze.py")
        .status()
        .expect("failed to run ML");

        let ml_results = crate::ml::inference::load_ml_results();
        for node in self.nodes.iter_mut() {
            node.apply_ml_results(&ml_results);
        }
    }

    pub fn reset_epoch_state(&mut self) {
        for node in self.nodes.iter_mut() {
            node.reset_epoch_state(); // you define this
        }
    }
}
use crate::network::node::Node;
use crate::network::message::{Message, Payload};
use crate::core::feldman_vss::tamper_share;
use crate::core::feldman_vss::generate_verified_shares;
use crate::ml::export::export_metrics;
use rand::Rng;

pub struct Simulation {
    pub nodes: Vec<Node>,
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

        Self { nodes }
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
        println!("\n🤝 Simulating honest traffic...\n");

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
        println!("\n🚨 Node {} launching attack...\n", attacker_id);

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
        println!("\n🧠 Evaluating network...\n");

        for node in self.nodes.iter_mut() {
            node.evaluate_network();
            node.tick();
        }

        // Step 4: resharing happens
        println!("\n🔁 Performing resharing...\n");

        for node in self.nodes.iter_mut() {
            node.perform_resharing();
        }

        export_metrics(&self.nodes);
    }
}
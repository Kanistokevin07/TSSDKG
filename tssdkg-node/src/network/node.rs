use std::collections::HashSet;
use std::collections::HashMap;

use crate::core::feldman_vss::{
    FeldmanShare,
    verify_share as feldman_verify,
    VerificationResult,
    Q_ORDER,
    P_MODULUS,
};

use crate::core::feldman_vss::{generate_verified_shares, tamper_share};

use crate::ml::inference::MLResult;

use crate::network::message::*;
use crate::security::{
    detection::{DetectionEvent, Detector},
    epoch::EpochManager,
    reputation::PeerState,
    resharing::ResharingEngine,
};

pub struct Node {
    pub id: NodeId,
    pub epoch_mgr: EpochManager,
    pub peers: HashMap<NodeId, PeerState>,
    pub share: i64,
    pub threshold: usize,
    pub needs_resharing: bool,
    pub handled_malicious: HashMap<u64, HashSet<u32>>, // epoch → handled nodes
    pub resharing_triggered_epoch: Option<u64>,
    pub last_reshared_epoch: u64,
}



impl Node {
    pub fn new(id: NodeId, threshold: usize, share: i64) -> Self {
        Self {
            id,
            epoch_mgr: EpochManager::new(),
            peers: HashMap::new(),
            share,
            threshold,
            needs_resharing: false,
            handled_malicious: HashMap::new(),
            resharing_triggered_epoch: None,
            last_reshared_epoch: 0,
        }
    }

    pub fn handle_message(&mut self, msg: Message) {
      let current_epoch = self.epoch_mgr.get();

      if let Some(peer) = self.peers.get_mut(&msg.from) {
        peer.total_messages += 1;
        peer.epochs_participated += 1;
     }

      println!(" Received message from {} at epoch {}", msg.from, msg.epoch);

      // 🚨 Replay protection
      if msg.epoch != current_epoch {
        if let Some(peer) = self.peers.get_mut(&msg.from) {
            peer.replay_count += 1; 
            Detector::detect(DetectionEvent::ReplayAttack, peer);
        }

        // 🔥 DO NOT RETURN — still evaluate network
        self.evaluate_network();
        return;
    }

        match msg.payload {
            Payload::Share(fs) => {
            println!(" Verifying share from {}", msg.from);

            // 1️⃣ Extract fs data first
            let valid = self.verify_share(&fs);

            // 2️⃣ Borrow peer mutably after
            if let Some(peer) = self.peers.get_mut(&msg.from) {
                if !valid {
                    println!(" Invalid share detected from {}", msg.from);
                    peer.invalid_shares += 1;
                    Detector::detect(DetectionEvent::InvalidShare, peer);
                } else {
                    peer.valid_shares += 1;
                }
            }
        }
            _ => {}
        }

      self.evaluate_network();
  }

    pub fn verify_share(&self, fs: &FeldmanShare) -> bool {
        match feldman_verify(fs, Q_ORDER, P_MODULUS) {
            VerificationResult::Valid => true,
            VerificationResult::Invalid(msg) => {
                println!(" Verification failed: {}", msg);
                false
            }
        }
    }

    pub fn apply_ml_results(&mut self, results: &Vec<MLResult>) {
        for res in results {
            if let Some(peer) = self.peers.get_mut(&res.node_id) {
                if res.anomaly == 1 {
                    println!("🧠 ML flagged node {}", res.node_id);
                    peer.reputation -= 20;
                }
            }
        }
    }
    pub fn evaluate_network(&mut self) {
    // ------------------------
    // Layer 1: Rule-based detection
    // ------------------------
    for peer in self.peers.values_mut() {
        if peer.invalid_shares > 3 {
            println!(" Rule Layer flagged node {}", peer.id);
            peer.reputation -= 15;
        }

        if peer.replay_count > 2 {
            println!(" Replay detected for node {}", peer.id);
            peer.reputation -= 10;
        }
    }

    // ------------------------
    // Final decision layer (LOCAL only)
    // ------------------------
    let current_epoch = self.epoch_mgr.get();

    let handled_set = self
        .handled_malicious
        .entry(current_epoch)
        .or_insert(HashSet::new());

    for peer in self.peers.values_mut() {
        println!("👀 Checking peer {} | Reputation: {}", peer.id, peer.reputation);

        if peer.is_malicious() && !handled_set.contains(&peer.id) {
            println!("🚫 Node {} marked malicious!", peer.id);

            // ✅ ONLY mark locally
            handled_set.insert(peer.id);
        }
    }
}
    

    pub fn perform_resharing(&mut self) {
        if self.needs_resharing {
            let (new_share, new_epoch) =
                crate::security::resharing::ResharingEngine::trigger(
                    self.share,
                    self.threshold,
                    &self.epoch_mgr,
                );

            println!(
                "🔁 Node {} reshared → new share: {}, epoch: {}",
                self.id, new_share, new_epoch
            );

            self.share = new_share;
            self.needs_resharing = false;

            let current_epoch = self.epoch_mgr.get();
            // Keep only last 2 epochs (or 1)
            self.handled_malicious.retain(|&epoch, _| epoch >= current_epoch - 1);
        }
    }

    pub fn reset_epoch_state(&mut self) {
        for peer in self.peers.values_mut() {
            peer.reset_epoch_metrics();
        }

        self.handled_malicious.clear();
        self.needs_resharing = false;
    }

    pub fn should_flag_peer(&self, peer: &PeerState, ml_flag: bool) -> bool {
        let rule_flag = peer.is_malicious();

        // Fusion logic
        rule_flag || ml_flag
    }
}
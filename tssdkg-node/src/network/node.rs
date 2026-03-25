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
    pub handled_malicious: HashSet<u32>,
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
            handled_malicious: HashSet::new(),
        }
    }

    pub fn handle_message(&mut self, msg: Message) {
      let current_epoch = self.epoch_mgr.get();

      if let Some(peer) = self.peers.get_mut(&msg.from) {
        peer.total_messages += 1;
        peer.epochs_participated += 1;
     }

      println!("📩 Received message from {} at epoch {}", msg.from, msg.epoch);

      // 🚨 Replay protection
      if msg.epoch != current_epoch {
        if let Some(peer) = self.peers.get_mut(&msg.from) {
            Detector::detect(DetectionEvent::ReplayAttack, peer);
        }

        // 🔥 DO NOT RETURN — still evaluate network
        self.evaluate_network();
        return;
    }

      match msg.payload {
          Payload::Share(fs) => {
              println!("🔍 Verifying share from {}", msg.from);

              let valid = self.verify_share(&fs);

              if !valid {
                println!("❌ Invalid share detected from {}", msg.from);
                if let Some(peer) = self.peers.get_mut(&msg.from) {
                    peer.invalid_shares += 1;   // ✅ ADD THIS LINE
                    Detector::detect(DetectionEvent::InvalidShare, peer);
                }
              }
              else{
                peer.valid_shares += 1;
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
                println!("❌ Verification failed: {}", msg);
                false
            }
        }
    }

    pub fn evaluate_network(&mut self) {
        for peer in self.peers.values_mut() {
            println!("👀 Checking peer {} | Reputation: {}", peer.id, peer.reputation);

            if peer.is_malicious() {
                // 🔥 NEW CHECK
                if !self.handled_malicious.contains(&peer.id) {
                    println!("🚫 Node {} marked malicious!", peer.id);

                    let (new_share, new_epoch) =
                        ResharingEngine::trigger(self.share, self.threshold, &self.epoch_mgr);

                    println!("🔁 Resharing triggered!");
                    println!("   Old share: {}", self.share);
                    println!("   New share: {}", new_share);
                    println!("   New epoch: {}", new_epoch);

                    self.share = new_share;
                    self.needs_resharing = true;

                    // 🔥 MARK AS HANDLED
                    self.handled_malicious.insert(peer.id);
                }
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
        }
    }
}
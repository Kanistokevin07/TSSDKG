use std::collections::HashMap;

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
}

impl Node {
    pub fn new(id: NodeId, threshold: usize, share: i64) -> Self {
        Self {
            id,
            epoch_mgr: EpochManager::new(),
            peers: HashMap::new(),
            share,
            threshold,
        }
    }

    pub fn handle_message(&mut self, msg: Message) {
      let current_epoch = self.epoch_mgr.get();

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
          Payload::Share(data) => {
              println!("🔍 Verifying share from {}", msg.from);

              let valid = self.verify_share(&data);

              if !valid {
                  println!("❌ Invalid share detected from {}", msg.from);

                  if let Some(peer) = self.peers.get_mut(&msg.from) {
                      Detector::detect(DetectionEvent::InvalidShare, peer);
                  }
              }
          }
          _ => {}
      }

      self.evaluate_network();
  }

    fn verify_share(&self, _data: &[u8]) -> bool {
        // 🔥 Hook your Feldman verification here
        true
    }

    fn evaluate_network(&mut self) {
    for peer in self.peers.values_mut() {
        println!("👀 Checking peer {} | Reputation: {}", peer.id, peer.reputation);

        if peer.is_malicious() {
            println!("🚫 Node {} marked malicious!", peer.id);

            let (new_share, new_epoch) =
                ResharingEngine::trigger(self.share, self.threshold, &self.epoch_mgr);

            println!("🔁 Resharing triggered!");
            println!("   Old share: {}", self.share);
            println!("   New share: {}", new_share);
            println!("   New epoch: {}", new_epoch);

            self.share = new_share;
        }
    }
}
}
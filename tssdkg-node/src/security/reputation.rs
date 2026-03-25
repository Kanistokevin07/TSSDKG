use crate::network::message::NodeId;

#[derive(Debug)]
pub struct PeerState {
    pub id: NodeId,
    pub reputation: i32,
    pub invalid_shares: u32,
    pub total_messages: u32,
    pub replay_count: u32,
    pub valid_shares: u32,
    pub epochs_participated: u32,
}

impl PeerState {
    pub fn new(id: NodeId) -> Self {
        Self {
            id,
            reputation: 100,
            invalid_shares: 0,
            total_messages: 0,
        }
    }

    pub fn penalize(&mut self, value: i32) {
        self.reputation -= value;
        if self.reputation < 0 {
            self.reputation = 0;
        }
    }

    pub fn reward(&mut self) {
        self.reputation += 2;
        if self.reputation > 100 {
            self.reputation = 100;
        }
    }

    pub fn is_malicious(&self) -> bool {
        self.reputation == 0
    }
}
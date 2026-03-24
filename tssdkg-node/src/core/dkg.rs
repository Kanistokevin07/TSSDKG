use super::feldman_vss::{FeldmanShare, generate_verified_shares, Q_ORDER, P_MODULUS};
use super::shamir::Share;

#[derive(Debug)]
pub struct DKGParticipant {
    pub id: u64,
    pub threshold: usize,
    pub public_key: u64,
    pub total_nodes: usize,
    
    // Round 1 Data: The shares this node generated for OTHERS
    pub my_generated_shares: Vec<FeldmanShare>,
    
    // Round 2 Data: The shares this node received FROM others
    pub received_shares: Vec<FeldmanShare>,
    
    // The final result: This node's specific share of the GLOBAL secret
    pub final_secret_share: Option<u64>,
}

impl DKGParticipant {
    pub fn new(id: u64, n: usize, k: usize) -> Self {
        Self {
            id,
            total_nodes: n,
            threshold: k,
            public_key: 0,
            my_generated_shares: Vec::new(),
            received_shares: Vec::new(),
            final_secret_share: None,
        }
    }

    /// ROUND 1: Generate a local secret and create Feldman shares for everyone else.
    pub fn generate_contributions(&mut self, local_secret: u64) {
        // This node acts as a dealer for its own secret
        let shares = generate_verified_shares(
            local_secret, 
            self.total_nodes, 
            self.threshold, 
            Q_ORDER, 
            P_MODULUS
        );
        self.my_generated_shares = shares;
    }

    /// SIMULATION HELPER: Receive a share from another node
    pub fn receive_share(&mut self, share: FeldmanShare) {
        self.received_shares.push(share);
    }

    pub fn finalize_round_2(&mut self) -> Result<u64, String> {
        let mut aggregate_y: u64 = 0;
        let mut group_public_key: u128 = 1; // Use u128 for intermediate product to avoid overflow

        for (sender_idx, fs) in self.received_shares.iter().enumerate() {
            // 1. Verify the share against its commitments
            match super::feldman_vss::verify_share(fs, Q_ORDER, P_MODULUS) {
                super::feldman_vss::VerificationResult::Valid => {
                    // 2. Add to aggregate share (modulo Q)
                    aggregate_y = (aggregate_y + fs.share.y) % Q_ORDER;

                    // 3. Contribute to Group Public Key (Product of C0 modulo P)
                    // fs.commitments[0] is g^(secret_j)
                    let c0 = fs.commitments[0] as u128;
                    group_public_key = (group_public_key * c0) % P_MODULUS as u128;
                }
                super::feldman_vss::VerificationResult::Invalid(msg) => {
                    return Err(format!("Node {} sent a fraudulent share: {}", sender_idx + 1, msg));
                }
            }
        }

        self.final_secret_share = Some(aggregate_y);
        self.public_key = group_public_key as u64;

        Ok(self.public_key)
    }

    
}


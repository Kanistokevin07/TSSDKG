use crate::core::feldman_vss::{Q_ORDER, P_MODULUS};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone)]
pub struct PartialSignature {
    pub node_id: u64,
    pub s_i: u64,
}

pub fn calculate_challenge(public_key: u64, message: &str) -> u64 {
    let mut s = DefaultHasher::new();
    public_key.hash(&mut s);
    message.hash(&mut s);
    s.finish() % Q_ORDER
}

/// Each node signs using: s_i = r_i + e * x_i
/// For this simple TSS demo, we assume a deterministic nonce r_i for simplicity.
pub fn sign_partial(node_id: u64, share_y: u64, public_key: u64, message: &str) -> PartialSignature {
    let e = calculate_challenge(public_key, message);
    
    // In a production DKG, r_i is generated via a separate DKG round.
    // Here, we use a mock nonce to demonstrate the algebraic aggregation.
    let r_i = 12345; 
    let s_i = (r_i + (e * share_y)) % Q_ORDER;
    
    PartialSignature { node_id, s_i }
}

pub fn aggregate_signatures(partials: &[PartialSignature], threshold: usize) -> u64 {
      // In a real Schnorr TSS, you apply Lagrange interpolation constants 
      // to the s_i values to account for the Shamir polynomial.
      
      // Simplified Aggregation for Demo:
      let mut total_s = 0;
      for p in partials.iter().take(threshold) {
          total_s = (total_s + p.s_i) % Q_ORDER;
      }
      total_s
  }
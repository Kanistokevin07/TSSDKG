use crate::core::shamir::{generate_zero_polynomial, evaluate_polynomial};
use crate::security::epoch::EpochManager;

pub struct ResharingEngine;

impl ResharingEngine {
    pub fn trigger(
        current_share: i64,
        threshold: usize,
        epoch_mgr: &EpochManager,
    ) -> (i64, u64) {
        // Generate zero polynomial
        let poly = generate_zero_polynomial(threshold);

        // Evaluate for this node (assume node_id = x)
        let node_id = 1; // replace with actual node id
        let new_share = evaluate_polynomial(&poly, node_id as i64);

        // Add shares
        let updated_share = current_share + new_share;

        // Move to next epoch
        let new_epoch = epoch_mgr.next();

        (updated_share, new_epoch)
    }
}
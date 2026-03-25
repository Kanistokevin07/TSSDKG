use crate::core::feldman_vss::FeldmanShare;

pub type NodeId = u32;

#[derive(Debug, Clone)]
pub enum Payload {
    Share(FeldmanShare),   // 🔥 REAL SHARE
    Commitment(Vec<u64>),
    Signature(Vec<u8>),
    Ping,
}

#[derive(Debug, Clone)]
pub struct Message {
    pub from: NodeId,
    pub epoch: u64,
    pub payload: Payload,
}
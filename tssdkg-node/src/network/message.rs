use crate::security::epoch::Epoch;

pub type NodeId = u32;

#[derive(Debug, Clone)]
pub enum Payload {
    Share(Vec<u8>),
    Commitment(Vec<u8>),
    Signature(Vec<u8>),
    Ping,
}

#[derive(Debug, Clone)]
pub struct Message {
    pub from: NodeId,
    pub epoch: Epoch,
    pub payload: Payload,
}
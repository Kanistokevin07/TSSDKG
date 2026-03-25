use crate::network::message::NodeId;

#[derive(Debug)]
pub enum DetectionEvent {
    InvalidShare,
    CommitmentMismatch,
    ReplayAttack,
    Timeout,
}

pub struct Detector;

impl Detector {
    pub fn detect(event: DetectionEvent, peer: &mut super::reputation::PeerState) {
        match event {
            DetectionEvent::InvalidShare => peer.penalize(40),
            DetectionEvent::CommitmentMismatch => peer.penalize(30),
            DetectionEvent::ReplayAttack => peer.penalize(50),
            DetectionEvent::Timeout => peer.penalize(10),
        }
    }
}
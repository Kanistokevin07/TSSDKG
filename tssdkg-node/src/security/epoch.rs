use std::sync::atomic::{AtomicU64, Ordering};

pub type Epoch = u64;

pub struct EpochManager {
    current: AtomicU64,
}

impl EpochManager {
    pub fn new() -> Self {
        Self {
            current: AtomicU64::new(0),
        }
    }

    pub fn get(&self) -> Epoch {
        self.current.load(Ordering::Relaxed)
    }

    pub fn next(&self) -> Epoch {
        self.current.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn set(&self, epoch: u64) {
        self.current.store(epoch, Ordering::SeqCst);
    }
}
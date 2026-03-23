#![allow(dead_code)]
#![allow(unused)]

mod core;
mod security;
mod network;
mod ml;

fn main() {
    println!("TSSDKG Node starting...");
    println!("Version: {}", "0.1.0");
    core::shamir::run_demo();
    core::feldman_vss::run_demo();
}
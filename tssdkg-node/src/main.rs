/*#![allow(dead_code)]
#![allow(unused)]

// Explicitly import the items the compiler is missing
use crate::core::dkg::DKGParticipant;
use crate::core::feldman_vss::Q_ORDER;
use crate::core::shamir;
use crate::core::signature::PartialSignature;


use network::node::Node;
use network::message::{Message, Payload};
use network::simulation::Simulation;

mod core;
mod security;
mod network;
mod ml;

fn main() {
    let mut node = Node::new(1, 3, 12345);

    // simulate peer
    node.peers.insert(2, security::reputation::PeerState::new(2));

    for i in 0..3 {
        println!("\n--- Attack Round {} ---", i + 1);

        let msg = Message {
            from: 2,
            epoch: 999,
            payload: Payload::Ping,
        };

        node.handle_message(msg);
    }

    let mut sim = Simulation::new(5, 3);

    println!("🚀 Starting multi-node simulation...\n");

    // run attack scenario
    sim.run_round(2);

    /*println!("TSSDKG Node starting...");
    println!("Version: 0.1.0");
    core::shamir::run_demo();
    core::feldman_vss::run_demo();
    run_full_dkg_demo(); // Call the local function*/
}

pub fn run_full_dkg_demo() {
    println!("\n=== Starting Pedersen DKG Protocol ===\n");
    let n = 3;
    let k = 2;

    let mut nodes: Vec<DKGParticipant> = (1..=n as u64)
        .map(|id| DKGParticipant::new(id, n, k))
        .collect();

    let local_secrets = vec![1000, 2000, 3000];
    let expected_total_secret: u64 = local_secrets.iter().sum::<u64>() % Q_ORDER;

    for i in 0..n {
        nodes[i].generate_contributions(local_secrets[i]);
    }

    for i in 0..n {
        let shares_from_i = nodes[i].my_generated_shares.clone();
        for j in 0..n {
            nodes[j].receive_share(shares_from_i[j].clone());
        }
    }

    println!("Nodes verifying and aggregating...");
    for node in nodes.iter_mut() {
        // We help the compiler here with a clear return type
        let _: u64 = node.finalize_round_2().expect("Verification failed!");
    }

    // Use shamir::Share directly since we imported it above
    let final_shares: Vec<shamir::Share> = nodes.iter()
        .map(|node| shamir::Share { 
            x: node.id, 
            y: node.final_secret_share.unwrap() 
        })
        .collect();

    let reconstructed = shamir::reconstruct_secret(&final_shares[0..k], Q_ORDER);

    println!("\nResults:");
    println!("Individual secrets summed to: {}", expected_total_secret);
    println!("DKG Reconstructed Secret:    {}", reconstructed);
    println!("Group Public Key:            {}", nodes[0].public_key);
    
    assert_eq!(reconstructed, expected_total_secret);
    println!("\nSUCCESS: The DKG produced a valid distributed key!");

    println!("\n=== Starting Threshold Signature Phase ===");
    let message = "Transaction: Move 100 BTC to Kanis";
    
    // 1. Nodes 1 and 2 (Threshold k=2) generate partial signatures
    let sig1 = core::signature::sign_partial(nodes[0].id, nodes[0].final_secret_share.unwrap(), nodes[0].public_key, message);
    let sig2 = core::signature::sign_partial(nodes[1].id, nodes[1].final_secret_share.unwrap(), nodes[1].public_key, message);
    
    let partials = vec![sig1, sig2];
    println!("Partial signatures collected from Node 1 and Node 2.");

    // 2. Aggregate the signatures
    let final_sig = core::signature::aggregate_signatures(&partials, k);
    println!("Aggregated Group Signature: {}", final_sig);

    println!("\n[Architect Note]: This signature can now be verified by anyone ");
    println!("using ONLY the Group Public Key ({})", nodes[0].public_key);

        run_full_demo();
}

    // Add these helper functions for clean terminal output

fn print_header(text: &str) {
    let border = "═".repeat(text.len() + 4);
    println!("\n╔{}╗", border);
    println!("║  {}  ║", text);
    println!("╚{}╝\n", border);
}

fn print_epoch(epoch: u32) {
    println!("\n{}", "─".repeat(50));
    println!("  EPOCH {}", epoch);
    println!("{}", "─".repeat(50));
}

fn print_reputation(nodes: &[(u32, i32, bool)]) {
    println!("\nNode Reputation Scores:");
    for (id, score, excluded) in nodes {
        if *excluded {
            println!("  Node {}: ---        ❌ EXCLUDED", id);
        } else {
            let bar = "█".repeat((*score / 10) as usize);
            let empty = "░".repeat((10 - score / 10) as usize);
            println!("  Node {}: {}{}  {}/100", id, bar, empty, score);
        }
    }
}

fn print_ml_result(node_id: u32, score: f64, confidence: f64) {
    println!("\n  🤖 ML Isolation Forest — Node {}:", node_id);
    println!("     Anomaly Score:  {:.3}", score);
    println!("     Confidence:     {:.1}%", confidence * 100.0);
    if confidence > 0.7 {
        println!("     Decision:       ANOMALOUS ⚠");
    } else {
        println!("     Decision:       NORMAL ✓");
    }
}

pub fn run_full_demo() {
    print_header("TSSDKG — Adaptive Threshold Cryptography");

    println!("Novel contributions being demonstrated:");
    println!("  1. Reactive resharing (triggered by attack, not timer)");
    println!("  2. Two-layer detection (cryptographic + ML behavioral)");
    println!("  3. Probabilistic reputation scoring");

    // Add a small delay between sections
    // so mentor can read each part
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Scene 1: Normal operation
    print_epoch(1);
    // ... your existing normal demo code

    std::thread::sleep(std::time::Duration::from_millis(1000));

    // Scene 2: Attack
    print_epoch(2);
    println!("  Injecting Byzantine attack on Node 3...");
    // ... your attack detection code

    std::thread::sleep(std::time::Duration::from_millis(1000));

    // Scene 3: Self healing
    print_epoch(3);
    println!("  ⚡ REACTIVE RESHARING TRIGGERED");
    // ... your resharing code

    print_header("DEMO COMPLETE — Zero Human Intervention Required");
}*/

#![allow(dead_code)]
#![allow(unused)]

mod core;
mod security;
mod network;
mod ml;
mod demo;

fn main() {
    demo::run_full_demo();
}
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;

use crate::network::node::Node;

pub fn export_metrics(nodes: &Vec<Node>) {
    let mut file = File::create("metrics.csv").unwrap();

    writeln!(file, "node_id,invalid_ratio,total_messages").unwrap();

    // 🔥 Aggregate data per peer
    let mut aggregate: HashMap<u32, (u32, u32)> = HashMap::new();

    for node in nodes {
        for peer in node.peers.values() {
            let entry = aggregate.entry(peer.id).or_insert((0, 0));

            entry.0 += peer.invalid_shares;   // total invalid
            entry.1 += peer.total_messages;   // total messages
        }
    }

    // 🔥 Write ONE row per peer
    for (peer_id, (invalid, total)) in aggregate {
        let ratio = if total == 0 {
            0.0
        } else {
            invalid as f64 / total as f64
        };

        writeln!(file, "{},{},{}", peer_id, ratio, total).unwrap();
    }

    println!("📊 Clean metrics exported (no duplicates)");
}
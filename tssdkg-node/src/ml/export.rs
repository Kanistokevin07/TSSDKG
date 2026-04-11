use std::collections::HashMap;
use std::fs::File;
use std::io::Write;

use crate::network::node::Node;

pub fn export_metrics(nodes: &Vec<Node>) {
    let mut file = File::create("metrics.csv").unwrap();

    // ✅ Include all relevant metrics
    writeln!(file, "node_id,invalid_ratio,validity_rate,total_messages,replay_count,epochs_participated").unwrap();

    // Aggregate data per peer
    let mut aggregate: HashMap<u32, (u32, u32, u32, u32, u32)> = HashMap::new();
    // (invalid_shares, valid_shares, total_messages, replay_count)

    for node in nodes {
        for peer in node.peers.values() {
            let entry = aggregate.entry(peer.id).or_insert((0, 0, 0, 0,0));

            entry.0 += peer.invalid_shares;   // total invalid
            entry.1 += peer.valid_shares;     // total valid
            entry.2 += peer.total_messages;   // total messages
            entry.3 += peer.replay_count;     // total replays
            entry.4 += peer.epochs_participated
        }
    }

    // Write ONE row per peer
    for (peer_id, (invalid, valid, total, replay, epochs_participated)) in aggregate {
        let invalid_ratio = if total == 0 {
            0.0
        } else {
            invalid as f64 / total as f64
        };

        let validity_rate = if total == 0 {
            0.0
        } else {
            valid as f64 / total as f64
        };

        writeln!(
            file,
            "{},{},{},{},{},{}",
            peer_id, invalid_ratio, validity_rate, total, replay, epochs_participated
        )
        .unwrap();
    }

    println!(" Clean metrics exported ");
}
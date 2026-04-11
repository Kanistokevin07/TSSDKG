use std::fs;

#[derive(serde::Deserialize)]
pub struct MLResult {
    pub node_id: u32,
    pub anomaly: i32,
}

pub fn load_ml_results() -> Vec<MLResult> {
    let path = "src/ml/ml_output.json"; // must match the Python output path
    match std::fs::read_to_string(path) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_else(|_| {
            println!(" ML output JSON malformed, returning empty results");
            vec![]
        }),
        Err(_) => {
            println!(" ML output file not found at {}. Returning empty ML results.", path);
            vec![]
        }
    }
}
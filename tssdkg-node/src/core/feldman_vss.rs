use super::shamir::Share;
use rand::Rng;

// ── CONSTANTS ──────────────────────────────────────────

// Q_ORDER is our polynomial modulus (Secret Space).
// It is the largest Sophie Germain prime under 2^31.
pub const Q_ORDER: u64 = 2147483543; 

// P_MODULUS is our group modulus (Commitment Space).
// It is the largest Safe Prime under 2^32 (P = 2Q + 1).
pub const P_MODULUS: u64 = 4294967087;

// GENERATOR has order Q. Because P ≡ 7 (mod 8), 
// the number 2 is a quadratic residue and has prime order Q.
pub const GENERATOR: u64 = 2;

// ── DATA STRUCTURES ────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FeldmanShare {
    pub share: Share,
    pub commitments: Vec<u64>,
}

#[derive(Debug)]
pub enum VerificationResult {
    Valid,
    Invalid(String),
}

// ── CORE FUNCTIONS ─────────────────────────────────────

pub fn generate_verified_shares(
    secret: u64,
    n: usize,
    k: usize,
    q_modulus: u64,
    p_modulus: u64,
) -> Vec<FeldmanShare> {
    let mut rng = rand::thread_rng();
    
    // Evaluate the polynomial modulo the generator's order (Q)
    let mut coefficients: Vec<u64> = vec![secret % q_modulus];
    for _ in 1..k {
        coefficients.push(rng.gen_range(1..q_modulus));
    }

    // Commitments are computed mod P_MODULUS
    let commitments: Vec<u64> = coefficients
        .iter()
        .map(|&c| mod_pow(GENERATOR, c, p_modulus))
        .collect();

    // Shares are evaluated mod Q_ORDER
    let shares: Vec<Share> = (1..=n as u64)
        .map(|x| {
            let y = coefficients
                .iter()
                .enumerate()
                .map(|(i, &c)| {
                    // Polynomial math must be mod Q
                    mod_mul(c, mod_pow(x, i as u64, q_modulus), q_modulus)
                })
                .fold(0u64, |acc, v| (acc + v) % q_modulus);
            Share { x, y }
        })
        .collect();

    shares.into_iter().map(|share| FeldmanShare {
        share,
        commitments: commitments.clone(),
    }).collect()
}

pub fn verify_share(fs: &FeldmanShare, q_modulus: u64, p_modulus: u64) -> VerificationResult {
    let x = fs.share.x;
    let y = fs.share.y;

    // LHS is g^y mod P
    let lhs = mod_pow(GENERATOR, y, p_modulus);

    // RHS is product of (C_i ^ (x^i mod Q)) mod P
    let rhs = fs.commitments
        .iter()
        .enumerate()
        .fold(1u64, |acc, (i, &commitment)| {
            // Compute exponent: x^i mod Q
            let x_pow_i = mod_pow(x, i as u64, q_modulus); 

            // Commitment term: C_i^(x^i mod Q) mod P
            let term = mod_pow(commitment, x_pow_i, p_modulus);

            mod_mul(acc, term, p_modulus)
        });

    if lhs == rhs {
        VerificationResult::Valid
    } else {
        VerificationResult::Invalid(format!("LHS {} != RHS {}", lhs, rhs))
    }
}

pub fn tamper_share(fs: &FeldmanShare) -> FeldmanShare {
    let mut tampered = fs.clone();
    tampered.share.y = tampered.share.y.wrapping_add(1);
    tampered
}

// ── MATH UTILITIES ─────────────────────────────────────

// Fast modular exponentiation
fn mod_pow(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    if modulus == 1 {
        return 0;
    }
    let mut result = 1u64;
    base %= modulus;
    while exp > 0 {
        if exp & 1 == 1 {
            result = mod_mul(result, base, modulus);
        }
        exp >>= 1;
        base = mod_mul(base, base, modulus);
    }
    result
}

// Overflow-safe modular multiplication
fn mod_mul(a: u64, b: u64, modulus: u64) -> u64 {
    ((a as u128 * b as u128) % modulus as u128) as u64
}

// ── DEMO ───────────────────────────────────────────────

pub fn run_demo() {
    println!("\n=== Feldman VSS Demo ===\n");

    let secret = 42_000_000u64;
    let n = 5;
    let k = 3;

    println!("Secret:    {}", secret);
    println!("Nodes:     {}", n);
    println!("Threshold: {}", k);

    // FIX: Using P_MODULUS instead of the old PRIME from shamir.rs
    let shares = generate_verified_shares(secret, n, k, Q_ORDER, P_MODULUS);

    println!("\nPublic commitments:");
    for (i, c) in shares[0].commitments.iter().enumerate() {
        println!("  C{} = {}", i, c);
    }

    println!("\nPrivate shares:");
    for fs in &shares {
        println!("  Node {}: y = {}", fs.share.x, fs.share.y);
    }

    println!("\nVerification:");
    for fs in &shares {
        match verify_share(fs, Q_ORDER, P_MODULUS) {
            VerificationResult::Valid => {
                println!("  Node {}: VALID", fs.share.x);
            }
            VerificationResult::Invalid(msg) => {
                println!("  Node {}: INVALID — {}", fs.share.x, msg);
            }
        }
    }

    println!("\n--- Attack simulation ---");
    let tampered = tamper_share(&shares[2]);
    println!("Tampered Node 3 share by +1");
    match verify_share(&tampered, Q_ORDER, P_MODULUS) {
        VerificationResult::Valid => println!("  VALID (should not happen)"),
        VerificationResult::Invalid(msg) => println!("  CAUGHT: {}", msg),
    }
}

// ── TESTS ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    // Notice: We only import reconstruct_secret, we don't import PRIME here anymore.
    use super::super::shamir::reconstruct_secret;

    #[test]
    fn test_all_valid_shares_verify() {
        let shares = generate_verified_shares(42000000u64, 5, 3, Q_ORDER, P_MODULUS);
        for fs in &shares {
            assert!(
                matches!(verify_share(fs, Q_ORDER, P_MODULUS), VerificationResult::Valid),
                "Node {} should be valid", fs.share.x
            );
        }
    }

    #[test]
    fn test_tampered_share_detected() {
        let shares = generate_verified_shares(99999u64, 5, 3, Q_ORDER, P_MODULUS);
        let tampered = tamper_share(&shares[0]);
        assert!(
            matches!(verify_share(&tampered, Q_ORDER, P_MODULUS), VerificationResult::Invalid(_)),
            "Tampered share must be caught"
        );
    }

    #[test]
    fn test_corrupted_commitment_detected() {
        let mut shares = generate_verified_shares(77777u64, 5, 3, Q_ORDER, P_MODULUS);
        shares[0].commitments[0] = shares[0].commitments[0].wrapping_add(1);
        assert!(
            matches!(verify_share(&shares[0], Q_ORDER, P_MODULUS), VerificationResult::Invalid(_)),
            "Bad commitment must be caught"
        );
    }

    #[test]
    fn test_reconstruction_still_works() {
        let secret = 55555u64;
        let fshares = generate_verified_shares(secret, 5, 3, Q_ORDER, P_MODULUS);
        let plain: Vec<Share> = fshares.iter()
            .map(|fs| fs.share.clone())
            .collect();
        // Notice: Reconstruction happens strictly in Q_ORDER.
        let result = reconstruct_secret(&plain[0..3], Q_ORDER);
        assert_eq!(result, secret);
    }

    #[test]
    fn test_different_secrets_different_commitments() {
        let s1 = generate_verified_shares(11111u64, 5, 3, Q_ORDER, P_MODULUS);
        let s2 = generate_verified_shares(22222u64, 5, 3, Q_ORDER, P_MODULUS);
        assert_ne!(
            s1[0].commitments[0],
            s2[0].commitments[0],
            "Different secrets must produce different C0"
        );
    }
}
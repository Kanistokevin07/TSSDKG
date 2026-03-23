// ═══════════════════════════════════════════════════════
// FELDMAN VERIFIABLE SECRET SHARING
// Based on: Feldman 1987
// "A Practical Scheme for Non-Interactive VSS"
//
// Extends Shamir Secret Sharing with cryptographic
// commitments so any node can verify their share
// is genuine without knowing the secret.
//
// Key insight:
// Commitments use the homomorphic property of
// modular exponentiation:
//   g^(a+b) = g^a * g^b mod p
// This lets us verify polynomial evaluation
// without revealing polynomial coefficients.
// ═══════════════════════════════════════════════════════

// super:: means "go up one level to parent module"
// We are in core::feldman_vss
// super = core
// super::shamir = core::shamir
// We reuse Share and math from shamir.rs
// No need to rewrite what already works
use super::shamir::{generate_shares, Share, PRIME};
use rand::Rng;

// ── CONSTANTS ──────────────────────────────────────────

// Generator g for commitment scheme
// We use 2 as our generator
// In production this would be a carefully chosen
// generator of a cryptographic group
// For our prime field this works correctly
// because 2 is a primitive root mod our Mersenne prime
//
// Why a generator?
// g^x cycles through many values as x changes
// Making it computationally hard to find x from g^x
// This is the Discrete Logarithm Problem (DLP)
// Security of Feldman VSS relies on DLP hardness
pub const GENERATOR: u64 = 2;

// A larger safe prime for commitment operations
// Our PRIME from shamir.rs is used for polynomial math
// We use the same prime here for the commitment group
// In production you would use a larger safe prime
// but for our demonstration this is sufficient
pub const COMMIT_PRIME: u64 = PRIME;

// ── DATA STRUCTURES ────────────────────────────────────

// FeldmanShare extends a basic Share with commitments
// The dealer publishes commitments once
// Every node receives the SAME commitments
// but a DIFFERENT share
//
// #[derive(Debug, Clone)] = auto generate
//   Debug  → can print with {:?}
//   Clone  → can duplicate with .clone()
#[derive(Debug, Clone)]
pub struct FeldmanShare {
    // The actual share (x, y) — same as before
    // pub = accessible outside this module
    pub share: Share,

    // Commitments to polynomial coefficients
    // Vec<u64> = variable length array of u64 values
    // One commitment per coefficient
    // For threshold k, there are k commitments
    // C[0] = g^a0, C[1] = g^a1, ..., C[k-1] = g^(a(k-1))
    pub commitments: Vec<u64>,
}

// Result of share verification
// Using an enum here instead of bool
// because Rust enums can carry data
// and are more expressive than true/false
//
// enum = a type that can be one of several variants
// Like a union in C++ but safe
// Like an enum in Python but more powerful
#[derive(Debug)]
pub enum VerificationResult {
    // Valid variant carries no extra data
    // Just means "the share checked out"
    Valid,

    // Invalid variant carries a String explaining WHY
    // String = owned heap allocated string
    // &str = borrowed string reference
    // We use String here because we own the message
    Invalid(String),
}

// ── MAIN FUNCTIONS ─────────────────────────────────────

// Generate shares WITH commitments
// Returns Vec<FeldmanShare> — each node gets one
// All nodes get the SAME commitments inside their share
//
// Parameters same as generate_shares in shamir.rs
// but now we also produce commitments
pub fn generate_verified_shares(
    secret: u64,
    n: usize,
    k: usize,
) -> Vec<FeldmanShare> {

    let mut rng = rand::thread_rng();

    // Build polynomial coefficients manually here
    // because we need them to create commitments
    // In shamir.rs they were created internally
    // Here we need to keep them to compute commitments
    //
    // mut = will be modified (push values in)
    // Vec<u64> = vector of unsigned 64-bit integers
    let mut coefficients: Vec<u64> = Vec::new();

    // First coefficient IS the secret (constant term)
    // f(0) = secret = a0
    coefficients.push(secret);

    // Remaining k-1 coefficients are random
    // These make the sharing secure —
    // without them all shares would be predictable
    for _ in 1..k {
        coefficients.push(rng.gen_range(1..PRIME));
    }

    // ── Compute commitments ──────────────────────────
    // For each coefficient ai, compute g^ai mod p
    // This is the commitment to that coefficient
    //
    // .iter() = borrow each element
    // .map(|&c| ...) = transform each coefficient c
    //   &c = destructure reference to get value c
    // mod_pow(GENERATOR, c, COMMIT_PRIME) = g^c mod p
    // .collect() = gather into Vec<u64>
    let commitments: Vec<u64> = coefficients
        .iter()
        .map(|&c| mod_pow(GENERATOR, c, COMMIT_PRIME))
        .collect();

    // ── Generate shares using our coefficients ───────
    // Evaluate polynomial f(x) at x = 1..n
    // Same math as shamir.rs but using OUR coefficients
    // not randomly generated ones inside generate_shares
    let shares: Vec<Share> = (1..=n as u64)
        .map(|x| {
            // Evaluate polynomial at x:
            // y = a0 + a1*x + a2*x^2 + ... mod PRIME
            let y = coefficients
                .iter()
                .enumerate()
                .map(|(i, &c)| {
                    // c * x^i mod PRIME
                    mod_mul(c, mod_pow(x, i as u64, PRIME), PRIME)
                })
                // Sum all terms mod PRIME
                .fold(0u64, |acc, v| (acc + v) % PRIME);

            Share { x, y }
        })
        .collect();

    // ── Combine into FeldmanShares ───────────────────
    // Each node gets their share PLUS all commitments
    // shares.into_iter() = consuming iterator
    //   (takes ownership of each Share)
    // .map(|share| ...) = wrap each Share in FeldmanShare
    // commitments.clone() = duplicate commitments for each node
    //   All nodes get the SAME commitments
    //   Each node gets a DIFFERENT share
    shares
        .into_iter()
        .map(|share| FeldmanShare {
            share,
            // Clone commitments for each FeldmanShare
            // because each FeldmanShare needs its own copy
            // Rust ownership: you cannot give the same
            // Vec to multiple owners
            commitments: commitments.clone(),
        })
        .collect()
}

// Verify a share against its commitments
// Returns VerificationResult::Valid or Invalid(reason)
//
// &FeldmanShare = borrow the share (just read it)
// We do not need ownership — just checking
pub fn verify_share(fs: &FeldmanShare) -> VerificationResult {
    let x = fs.share.x;
    let y = fs.share.y;

    // ── Left side: g^y mod p ─────────────────────────
    let lhs = mod_pow(GENERATOR, y, COMMIT_PRIME);

    // ── Right side: product of Ci^(x^i) mod p ───────
    // CRITICAL: x^i must NOT be reduced mod p
    // The exponent lives in Z_(p-1) not Z_p
    // For small x (node indices 1-20) x^i fits in u64
    // We compute x^i as plain integer power
    let rhs = fs.commitments
        .iter()
        .enumerate()
        .fold(1u64, |acc, (i, &commitment)| {
            // Compute x^i as plain integer
            // x is at most 20 (node index)
            // i is at most k-1 (threshold - 1)
            // 20^10 fits safely in u64
            // pow(i as u32) = integer power, no modular reduction
            let x_pow_i = x.pow(i as u32);

            // Now compute commitment^(x^i) mod p
            // This is Ci^(x^i) mod p
            let term = mod_pow(commitment, x_pow_i, COMMIT_PRIME);

            // Multiply into running product mod p
            mod_mul(acc, term, COMMIT_PRIME)
        });

    if lhs == rhs {
        VerificationResult::Valid
    } else {
        VerificationResult::Invalid(format!(
            "Share verification failed for node {}. \
             LHS={} RHS={}. Share may be tampered.",
            x, lhs, rhs
        ))
    }
}

// Tamper with a share to simulate a malicious dealer
// Used in tests and attack demonstrations
// Takes a FeldmanShare and returns a corrupted copy
pub fn tamper_share(fs: &FeldmanShare) -> FeldmanShare {
    // Clone the entire FeldmanShare
    // clone() = deep copy (new independent copy)
    // Required because we want to modify a copy
    // not the original
    let mut tampered = fs.clone();

    // Add 1 to y value — tiny change, huge effect
    // Even a 1-bit change breaks verification completely
    // This is the power of cryptographic commitments
    // .wrapping_add(1) = add 1 with overflow protection
    // If y is u64::MAX, wrapping_add wraps to 0
    // instead of panicking on overflow
    tampered.share.y = tampered.share.y.wrapping_add(1);
    tampered
}

// ── MATH UTILITIES ─────────────────────────────────────
// Same functions as in shamir.rs
// In a real project we would put these in a shared
// utils module to avoid duplication
// For now we keep them here for clarity

fn mod_pow(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result = 1u64;
    base %= modulus;
    while exp > 0 {
        if exp % 2 == 1 {
            result = mod_mul(result, base, modulus);
        }
        exp /= 2;
        base = mod_mul(base, base, modulus);
    }
    result
}

fn mod_mul(a: u64, b: u64, modulus: u64) -> u64 {
    ((a as u128 * b as u128) % modulus as u128) as u64
}

// ── DEMO FUNCTION ──────────────────────────────────────

pub fn run_demo() {
    println!("\n=== Feldman VSS Demo ===\n");

    let secret = 42_000_000u64;
    let n = 5;
    let k = 3;

    println!("Secret:    {}", secret);
    println!("Nodes:     {}", n);
    println!("Threshold: {}", k);

    // Generate shares with commitments
    let shares = generate_verified_shares(secret, n, k);

    // Show commitments — these are PUBLIC
    // Every node sees these
    println!("\nPublic commitments (published by dealer):");
    for (i, c) in shares[0].commitments.iter().enumerate() {
        println!("  C{} = {}", i, c);
    }

    // Show each node's share — these are PRIVATE
    // Each node only sees their own share
    println!("\nPrivate shares (each node sees only theirs):");
    for fs in &shares {
        println!("  Node {}: y = {}", fs.share.x, fs.share.y);
    }

    // Verify all shares — all should be valid
    println!("\nVerification of all shares:");
    for fs in &shares {
        match verify_share(fs) {
            // match = pattern matching
            // Like switch in C++ but exhaustive
            // Rust forces you to handle ALL variants
            // VerificationResult::Valid → print success
            // VerificationResult::Invalid(msg) → print error
            // msg binds the String inside Invalid
            VerificationResult::Valid => {
                println!("  Node {}: ✓ VALID", fs.share.x);
            }
            VerificationResult::Invalid(msg) => {
                println!("  Node {}: ✗ INVALID — {}", fs.share.x, msg);
            }
        }
    }

    // Now simulate a malicious dealer
    // Tamper with node 3's share
    println!("\n--- Simulating malicious dealer ---");
    println!("Tampering with Node 3's share...");

    let tampered = tamper_share(&shares[2]);

    println!("Original y:  {}", shares[2].share.y);
    println!("Tampered y:  {}", tampered.share.y);

    match verify_share(&tampered) {
        VerificationResult::Valid => {
            println!("Node 3: VALID (this should not happen!)");
        }
        VerificationResult::Invalid(msg) => {
            println!("Node 3: ✗ CAUGHT — {}", msg);
        }
    }
}

// ── TESTS ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_shares_verify() {
        // All generated shares should verify correctly
        let shares = generate_verified_shares(12345u64, 5, 3);
        for fs in &shares {
            assert!(
                matches!(verify_share(fs), VerificationResult::Valid),
                "Node {} share should be valid",
                fs.share.x
            );
        }
    }

    #[test]
    fn test_tampered_share_caught() {
        // A tampered share must NEVER verify as valid
        let shares = generate_verified_shares(99999u64, 5, 3);
        let tampered = tamper_share(&shares[0]);
        assert!(
            matches!(
                verify_share(&tampered),
                VerificationResult::Invalid(_)
            ),
            "Tampered share should be caught"
        );
    }

    #[test]
    fn test_wrong_commitment_caught() {
        // If commitments are wrong share verification fails
        let mut shares = generate_verified_shares(77777u64, 5, 3);

        // Corrupt the first commitment
        // This simulates a dishonest dealer who published
        // wrong commitments
        shares[0].commitments[0] = shares[0].commitments[0]
            .wrapping_add(1);

        assert!(
            matches!(
                verify_share(&shares[0]),
                VerificationResult::Invalid(_)
            ),
            "Wrong commitment should be caught"
        );
    }

    #[test]
    fn test_secret_still_reconstructable() {
        // VSS shares reconstruct same as plain Shamir
        use super::super::shamir::reconstruct_secret;

        let secret = 55555u64;
        let fshares = generate_verified_shares(secret, 5, 3);

        // Extract plain shares for reconstruction
        let plain_shares: Vec<Share> = fshares
            .iter()
            .map(|fs| fs.share.clone())
            .collect();

        let reconstructed = reconstruct_secret(&plain_shares[0..3], PRIME);
        assert_eq!(reconstructed, secret);
    }
}
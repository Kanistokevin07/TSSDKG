// Shamir Secret Sharing — the foundation of everything
// Based on: Shamir 1979

use rand::Rng;
pub const PRIME: u64 = 2_305_843_009_213_693_951; // Mersenne prime 2^61 - 1

/// A single share (x, y) where x is the node index
/// and y is the evaluated polynomial value
#[derive(Debug, Clone)]
pub struct Share {
    pub x: u64,
    pub y: u64,
}

pub type Polynomial = Vec<i64>;

pub fn evaluate_polynomial(poly: &Polynomial, x: i64) -> i64 {
    let mut result = 0;
    let mut power = 1;

    for &coeff in poly {
        result += coeff * power;
        power *= x;
    }

    result
}


pub fn generate_zero_polynomial(degree: usize) -> Polynomial {
    let mut rng = rand::thread_rng();

    let mut poly = vec![0]; // constant term = 0

    for _ in 0..degree {
        poly.push(rng.gen_range(1..100)); // random coefficients
    }

    poly
}

/// Split a secret into n shares where k are needed to reconstruct
pub fn generate_shares(
    secret: u64,
    n: usize,
    k: usize,
    prime: u64,
) -> Vec<Share> {
    assert!(k <= n, "Threshold k must be <= total shares n");
    assert!(k >= 2, "Threshold must be at least 2");

    let mut rng = rand::thread_rng();

    // Random polynomial: secret + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1)
    let mut coefficients = vec![secret];
    for _ in 1..k {
        coefficients.push(rng.gen_range(1..prime));
    }

    // Evaluate polynomial at x = 1, 2, ..., n
    (1..=n as u64)
        .map(|x| {
            let y = coefficients
                .iter()
                .enumerate()
                .map(|(i, &c)| {
                    mod_mul(c, mod_pow(x, i as u64, prime), prime)
                })
                .fold(0u64, |acc, v| (acc + v) % prime);
            Share { x, y }
        })
        .collect()
}

/// Reconstruct secret from k shares using Lagrange interpolation
pub fn reconstruct_secret(shares: &[Share], prime: u64) -> u64 {
    shares.iter().enumerate().fold(0u64, |acc, (i, share_i)| {
        let mut num = 1u64;
        let mut den = 1u64;

        for (j, share_j) in shares.iter().enumerate() {
            if i != j {
                num = mod_mul(num, (prime - share_j.x) % prime, prime);
                let diff = (prime + share_i.x - share_j.x) % prime;
                den = mod_mul(den, diff, prime);
            }
        }

        let lagrange = mod_mul(
            share_i.y,
            mod_mul(num, mod_inverse(den, prime), prime),
            prime,
        );
        (acc + lagrange) % prime
    })
}

// ── Math utilities ─────────────────────────────────────

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

fn mod_inverse(a: u64, prime: u64) -> u64 {
    // Fermat's little theorem: a^(p-2) mod p
    mod_pow(a, prime - 2, prime)
}

pub fn run_demo() {
    println!("\n=== Shamir Secret Sharing Demo ===\n");

    // Our secret value — in real system this would be
    // a cryptographic key, not a simple number
    let secret = 42_000_000u64;

    // 5 nodes total, any 3 can reconstruct
    // This means attacker must compromise 3+ nodes
    // to learn the secret
    let n = 5;
    let k = 3;

    println!("Secret:        {}", secret);
    println!("Total nodes:   {}", n);
    println!("Threshold:     {}", k);
    println!("Prime modulus: {}", PRIME);

    // Generate shares
    let shares = generate_shares(secret, n, k, PRIME);

    println!("\nGenerated shares (each node receives one):");
    for share in &shares {
        println!("  Node {}: y = {}", share.x, share.y);
    }

    // Reconstruct with shares 1, 2, 3
    let r1 = reconstruct_secret(&shares[0..3], PRIME);
    println!("\nReconstruct with nodes 1,2,3: {}", r1);
    println!("Correct: {}", r1 == secret);

    // Reconstruct with shares 2, 4, 5
    let r2 = reconstruct_secret(
        &[shares[1].clone(), shares[3].clone(), shares[4].clone()],
        PRIME,
    );
    println!("Reconstruct with nodes 2,4,5: {}", r2);
    println!("Correct: {}", r2 == secret);

    // Show that 2 shares are NOT enough
    let wrong = reconstruct_secret(&shares[0..2], PRIME);
    println!("\nReconstruct with only 2 nodes: {}", wrong);
    println!("Correct: {} (should be false)", wrong == secret);
}

// ── Tests ───────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const PRIME: u64 = 2_305_843_009_213_693_951; // Mersenne prime 2^61 - 1

    #[test]
    fn test_reconstruct_with_exactly_k_shares() {
        let secret = 42_000_000u64;
        let shares = generate_shares(secret, 5, 3, PRIME);

        // Any 3 shares reconstruct correctly
        let reconstructed = reconstruct_secret(&shares[0..3], PRIME);
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_different_k_shares_same_result() {
        let secret = 99_999_999u64;
        let shares = generate_shares(secret, 5, 3, PRIME);

        let r1 = reconstruct_secret(&[
            shares[0].clone(),
            shares[1].clone(),
            shares[2].clone()
        ], PRIME);
        let r2 = reconstruct_secret(&[
            shares[1].clone(),
            shares[3].clone(),
            shares[4].clone()
        ], PRIME);

        assert_eq!(r1, secret);
        assert_eq!(r2, secret);
    }

    #[test]
    fn test_fewer_than_k_shares_cannot_reconstruct() {
        let secret = 12_345_678u64;
        let shares = generate_shares(secret, 5, 3, PRIME);

        // 2 shares with threshold 3 should NOT reconstruct correctly
        let wrong = reconstruct_secret(&shares[0..2], PRIME);
        assert_ne!(wrong, secret);
    }
}
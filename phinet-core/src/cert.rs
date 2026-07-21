// phinet-core/src/cert.rs
//! ΦNET v2 Certificate System
//!
//! Construction: n = 2p where p is a (bits-1)-bit prime.
//!   φ(n) = p-1  (known from construction, no factoring needed)
//!   J = φ/μ + 1 (must be prime)
//!   μ ∈ {2, 4}  determined by digital_root(φ)
//!
//! J-first algorithm (fastest):
//!   1. Generate random (bits-2)-bit prime J
//!   2. Try μ=2: p = 2J-1  → need dr(p-1) ≥ 5 and p prime
//!   3. Try μ=4: p = 4J-3  → need dr(p-1) < 5 and p prime
//!   4. n = 2p; all fields known exactly

use crate::{Error, Result};
use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use tracing::{debug, info};

// ── Certificate bit sizes ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CertBits {
    B256  = 256,
    B512  = 512,
    B1024 = 1024,
    B2048 = 2048,
}

impl CertBits {
    pub fn bits(self) -> usize { self as usize }
    pub fn j_bits(self) -> usize { self as usize - 2 }
}

impl Default for CertBits {
    fn default() -> Self { CertBits::B256 }
}

impl fmt::Display for CertBits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.bits())
    }
}

// ── Wire representation ───────────────────────────────────────────────

/// JSON-safe certificate representation (big integers as hex strings).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireCert {
    pub n:    String,
    pub phi:  String,
    pub mu:   u8,
    pub j:    String,
    pub dr:   u8,
    pub sg:   u8,
    pub bits: CertBits,
}

impl Default for WireCert {
    fn default() -> Self {
        WireCert {
            n: String::new(), phi: String::new(), mu: 0,
            j: String::new(), dr: 0, sg: 0,
            bits: CertBits::B256,
        }
    }
}

// ── Certificate ───────────────────────────────────────────────────────

#[derive(Clone)]
pub struct PhiCert {
    pub n:    BigUint,
    pub phi:  BigUint,
    pub mu:   u8,
    pub j:    BigUint,
    pub dr:   u8,
    pub sg:   u8,
    pub bits: CertBits,
}

impl fmt::Debug for PhiCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let jh = self.j.to_str_radix(16);
        write!(f, "PhiCert({}-bit dr={} mu={} sg={} J={}…{})",
               self.bits.bits(), self.dr, self.mu, self.sg,
               &jh[..8.min(jh.len())],
               &jh[jh.len().saturating_sub(4)..])
    }
}

impl fmt::Display for PhiCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PhiCert({}-bit dr={} mu={} sg={})",
               self.bits.bits(), self.dr, self.mu, self.sg)
    }
}

// ── Math primitives ───────────────────────────────────────────────────

/// Digital root of n (returns 1-9, never 0).
pub fn digital_root(n: &BigUint) -> u8 {
    if n.is_zero() { return 9; }
    let r = (n % 9u32).to_u64_digits().first().copied().unwrap_or(0) as u8;
    if r == 0 { 9 } else { r }
}

/// Miller-Rabin primality test.
/// Deterministic for n < 3.3×10²⁴; probabilistic (40 rounds) for larger.
pub fn is_prime(n: &BigUint) -> bool {
    if n < &BigUint::from(2u32) { return false; }
    if n == &BigUint::from(2u32) || n == &BigUint::from(3u32) { return true; }
    if (n % 2u32).is_zero() { return false; }

    const SMALL: &[u64] = &[
        3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,
        101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,
        191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,
        281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,
        389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,
        491,499,503,509,521,523,541,
    ];
    for &p in SMALL {
        let bp = BigUint::from(p);
        if n == &bp { return true; }
        if (n % &bp).is_zero() { return false; }
    }

    let n_minus_1 = n - 1u32;
    let mut d = n_minus_1.clone();
    let mut s = 0u64;
    while (&d % 2u32).is_zero() { d >>= 1; s += 1; }

    let threshold = BigUint::parse_bytes(b"3317044064679887385961981", 10).unwrap();
    let det_witnesses: Vec<BigUint> = [2u64,3,5,7,11,13,17,19,23,29,31,37,41]
        .iter().map(|&w| BigUint::from(w)).collect();
    let witnesses: Vec<BigUint> = if n < &threshold {
        det_witnesses
    } else {
        let mut ws: Vec<BigUint> = [2u64,3,5,7,11,13,17,19,23,29,31,37,41,43,47]
            .iter().map(|&w| BigUint::from(w)).collect();
        for _ in 0..25 {
            ws.push(OsRng.gen_biguint_range(&BigUint::from(2u32), &(n - 1u32)));
        }
        ws
    };

    'witness: for a in &witnesses {
        let a = a % n;
        if a < BigUint::from(2u32) { continue; }
        let mut x = a.modpow(&d, n);
        if x.is_one() || x == n_minus_1 { continue; }
        for _ in 0..s - 1 {
            x = x.modpow(&BigUint::from(2u32), n);
            if x == n_minus_1 { continue 'witness; }
        }
        return false;
    }
    true
}

fn random_odd(bits: usize) -> BigUint {
    loop {
        let mut n = OsRng.gen_biguint(bits as u64);
        n.set_bit((bits - 1) as u64, true); // ensure exactly `bits` bits
        n.set_bit(0, true);                  // ensure odd
        if n.bits() as usize == bits { return n; }
    }
}

fn sieve_ok(n: &BigUint) -> bool {
    const S: &[u64] = &[
        3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,
        101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,
        191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,
        281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,
        389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,
        491,499,
    ];
    for &p in S {
        let bp = BigUint::from(p);
        if n == &bp { return true; }
        if (n % &bp).is_zero() { return false; }
    }
    true
}

// ── Generation ────────────────────────────────────────────────────────

impl PhiCert {
    /// Generate a new v2 certificate of the given bit size.
    pub fn generate(bits: CertBits) -> Result<Self> {
        let j_bits = bits.j_bits();
        let mut attempts = 0usize;
        info!("Generating ΦNET cert ({}-bit)…", bits.bits());

        loop {
            attempts += 1;
            let j = random_odd(j_bits);
            if !sieve_ok(&j) { continue; }

            // μ=2: p = 2J-1, need p prime and dr(p-1) ≥ 5
            {
                let p = &j * 2u32 - 1u32;
                if sieve_ok(&p) {
                    let phi = &p - 1u32;
                    let dr  = digital_root(&phi);
                    if dr >= 5 && is_prime(&j) && is_prime(&p) {
                        let sg = if is_prime(&(&j * 2u32 - 1u32)) { 1u8 } else { 0u8 };
                        let n  = &p * 2u32;
                        let c  = PhiCert { n, phi, mu: 2, j, dr, sg, bits };
                        info!("  Generated in {} attempts: {}", attempts, c);
                        return Ok(c);
                    }
                }
            }

            // μ=4: p = 4J-3, need p prime and dr(p-1) < 5
            {
                let p = &j * 4u32 - 3u32;
                if sieve_ok(&p) {
                    let phi = &p - 1u32;
                    let dr  = digital_root(&phi);
                    if dr < 5 && is_prime(&j) && is_prime(&p) {
                        let sg = if is_prime(&(&j * 2u32 - 1u32)) { 1u8 } else { 0u8 };
                        let n  = &p * 2u32;
                        let c  = PhiCert { n, phi, mu: 4, j, dr, sg, bits };
                        info!("  Generated in {} attempts: {}", attempts, c);
                        return Ok(c);
                    }
                }
            }

            if attempts % 50_000 == 0 {
                debug!("cert gen: {} attempts…", attempts);
            }
        }
    }

    /// Rotate to a new cert with a different n but same μ/dr class.
    pub fn rotate(&self) -> Result<Self> {
        info!("Rotating cert (same bit size, same class)…");
        Self::generate(self.bits)
    }

    /// Verify all certificate fields.
    pub fn verify(&self) -> bool {
        let two = BigUint::from(2u32);
        if (&self.n % &two) != BigUint::zero() { return false; }
        let p = &self.n / &two;
        if self.phi != (&p - 1u32) { return false; }
        if digital_root(&self.phi) != self.dr { return false; }
        let mu_exp = if self.dr >= 5 { 2u8 } else { 4u8 };
        if self.mu != mu_exp { return false; }
        if !(&self.phi % self.mu as u32).is_zero() { return false; }
        if self.phi.clone() / self.mu as u32 + 1u32 != self.j { return false; }
        if !is_prime(&self.j) { return false; }
        if !is_prime(&p) { return false; }
        let sg_exp = if is_prime(&(&self.j * 2u32 - 1u32)) { 1u8 } else { 0u8 };
        self.sg == sg_exp
    }

    /// 256-bit node ID: SHA-256(J_bytes ‖ φ_bytes ‖ 0x02)
    pub fn node_id(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.j.to_bytes_be());
        h.update(self.phi.to_bytes_be());
        h.update([0x02u8]);
        h.finalize().into()
    }

    pub fn node_id_hex(&self) -> String { hex::encode(self.node_id()) }

    /// φ-cluster ID: SHA-256(φ_bytes ‖ 0x02)
    pub fn cluster_id(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.phi.to_bytes_be());
        h.update([0x02u8]);
        h.finalize().into()
    }

    pub fn cluster_id_hex(&self) -> String { hex::encode(self.cluster_id()) }

    pub fn to_wire(&self) -> WireCert {
        WireCert {
            n:    hex::encode(self.n.to_bytes_be()),
            phi:  hex::encode(self.phi.to_bytes_be()),
            mu:   self.mu,
            j:    hex::encode(self.j.to_bytes_be()),
            dr:   self.dr,
            sg:   self.sg,
            bits: self.bits,
        }
    }

    pub fn from_wire(w: &WireCert) -> Result<Self> {
        Ok(PhiCert {
            n:    biguint_from_hex(&w.n)?,
            phi:  biguint_from_hex(&w.phi)?,
            mu:   w.mu,
            j:    biguint_from_hex(&w.j)?,
            dr:   w.dr,
            sg:   w.sg,
            bits: w.bits,
        })
    }
}

// ── BigUint helpers ───────────────────────────────────────────────────

pub fn biguint_from_hex(s: &str) -> Result<BigUint> {
    let bytes = hex::decode(s)
        .map_err(|e| Error::InvalidCert(format!("hex decode: {e}")))?;
    Ok(BigUint::from_bytes_be(&bytes))
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digital_root_values() {
        assert_eq!(digital_root(&BigUint::from(0u32)),  9);
        assert_eq!(digital_root(&BigUint::from(9u32)),  9);
        assert_eq!(digital_root(&BigUint::from(18u32)), 9);
        assert_eq!(digital_root(&BigUint::from(10u32)), 1);
        assert_eq!(digital_root(&BigUint::from(25u32)), 7);
    }

    #[test]
    fn is_prime_small() {
        assert!(!is_prime(&BigUint::from(0u32)));
        assert!(!is_prime(&BigUint::from(1u32)));
        assert!(is_prime(&BigUint::from(2u32)));
        assert!(is_prime(&BigUint::from(7919u32)));
        assert!(!is_prime(&BigUint::from(7921u32)));
    }

    #[test]
    fn cert_256_generates_and_verifies() {
        let cert = PhiCert::generate(CertBits::B256).unwrap();
        assert!(cert.verify(), "256-bit cert must verify");
        assert_eq!(cert.node_id().len(), 32);
    }

    #[test]
    fn cert_roundtrip() {
        let c  = PhiCert::generate(CertBits::B256).unwrap();
        let c2 = PhiCert::from_wire(&c.to_wire()).unwrap();
        assert!(c2.verify());
        assert_eq!(c.node_id(), c2.node_id());
    }
}

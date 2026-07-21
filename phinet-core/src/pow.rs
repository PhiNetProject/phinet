// phinet-core/src/pow.rs
//! Proof-of-Work: Argon2id admission PoW + Hashcash intro puzzles.

use crate::{
    cert::{CertBits, PhiCert},
    Error, Result,
};
use argon2::{
    password_hash::{rand_core::OsRng as Argon2OsRng, SaltString},
    Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier,
    Version, Algorithm,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Instant;
use tracing::info;

// ── Argon2id parameters by cert bit-size ──────────────────────────────

pub struct ArgonParams { pub m_cost: u32, pub t_cost: u32, pub p_cost: u32 }

impl ArgonParams {
    pub fn for_cert(bits: CertBits) -> Self {
        match bits {
            CertBits::B256  => ArgonParams { m_cost:     65_536, t_cost: 3, p_cost: 1 },
            CertBits::B512  => ArgonParams { m_cost:    262_144, t_cost: 4, p_cost: 1 },
            CertBits::B1024 => ArgonParams { m_cost:  1_048_576, t_cost: 5, p_cost: 2 },
            CertBits::B2048 => ArgonParams { m_cost:  4_194_304, t_cost: 6, p_cost: 4 },
        }
    }
}

// ── Admission PoW ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionPoW {
    pub hash:   String,
    pub salt:   String,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

pub fn solve_admission(cert: &PhiCert) -> Result<AdmissionPoW> {
    let p    = ArgonParams::for_cert(cert.bits);
    let pass = cert_canonical_bytes(cert);
    let salt = SaltString::generate(&mut Argon2OsRng);

    let params = Params::new(p.m_cost, p.t_cost, p.p_cost, None)
        .map_err(|e| Error::PowFailed(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let t0   = Instant::now();
    let hash = argon2
        .hash_password(&pass, &salt)
        .map_err(|e| Error::PowFailed(e.to_string()))?
        .to_string();

    info!(
        "Admission PoW: {:.2}s  m={}KiB t={} p={}",
        t0.elapsed().as_secs_f64(),
        p.m_cost / 1024, p.t_cost, p.p_cost,
    );
    Ok(AdmissionPoW { hash, salt: salt.to_string(), m_cost: p.m_cost, t_cost: p.t_cost, p_cost: p.p_cost })
}

pub fn verify_admission(cert: &PhiCert, pow: &AdmissionPoW) -> bool {
    let pass   = cert_canonical_bytes(cert);
    let params = match Params::new(pow.m_cost, pow.t_cost, pow.p_cost, None) {
        Ok(p)  => p,
        Err(_) => return false,
    };
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let parsed = match PasswordHash::new(&pow.hash) {
        Ok(h)  => h,
        Err(_) => return false,
    };
    argon2.verify_password(&pass, &parsed).is_ok()
}

fn cert_canonical_bytes(cert: &PhiCert) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&cert.j.to_bytes_be());
    b.extend_from_slice(&cert.phi.to_bytes_be());
    b.push(cert.mu);
    b.push(cert.dr);
    b.push(0x02); // v2 cert
    b
}

// ── Introduction puzzle ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntroPuzzle {
    pub challenge:  String,
    pub difficulty: u8,
    pub issued_at:  u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntroPuzzleSolution {
    pub challenge: String,
    pub nonce:     u64,
}

impl IntroPuzzle {
    pub fn generate(difficulty: u8) -> Self {
        let mut ch = [0u8; 32];
        OsRng.fill_bytes(&mut ch);
        IntroPuzzle {
            challenge:  hex::encode(ch),
            difficulty,
            issued_at:  unix_now(),
        }
    }

    pub fn solve(&self) -> Result<IntroPuzzleSolution> {
        let cb = hex::decode(&self.challenge)
            .map_err(|e| Error::PowFailed(e.to_string()))?;
        for nonce in 0u64.. {
            let mut input = cb.clone();
            input.extend_from_slice(&nonce.to_le_bytes());
            if leading_zeros(&Sha256::digest(&input)) >= self.difficulty as usize {
                return Ok(IntroPuzzleSolution { challenge: self.challenge.clone(), nonce });
            }
        }
        Err(Error::PowFailed("exhausted".into()))
    }

    pub fn verify(&self, sol: &IntroPuzzleSolution) -> bool {
        if sol.challenge != self.challenge { return false; }
        let Ok(cb) = hex::decode(&self.challenge) else { return false };
        let mut input = cb;
        input.extend_from_slice(&sol.nonce.to_le_bytes());
        leading_zeros(&Sha256::digest(&input)) >= self.difficulty as usize
    }

    pub fn is_fresh(&self) -> bool {
        unix_now().saturating_sub(self.issued_at) < 120
    }
}

// ── Puzzle controller ─────────────────────────────────────────────────

pub struct PuzzleController {
    pub target_rps: f64,
    pub difficulty: u8,
    recent:         std::collections::VecDeque<std::time::Instant>,
    window_secs:    f64,
}

impl PuzzleController {
    pub fn new(target_rps: f64) -> Self {
        Self { target_rps, difficulty: 16, recent: Default::default(), window_secs: 10.0 }
    }

    pub fn record_request(&mut self) -> u8 {
        let now = std::time::Instant::now();
        self.recent.push_back(now);
        let cutoff = now - std::time::Duration::from_secs_f64(self.window_secs);
        while self.recent.front().map_or(false, |t| *t < cutoff) { self.recent.pop_front(); }
        let rps = self.recent.len() as f64 / self.window_secs;
        if      rps > self.target_rps * 2.0 { self.difficulty = self.difficulty.saturating_add(2).min(28); }
        else if rps > self.target_rps       { self.difficulty = self.difficulty.saturating_add(1).min(28); }
        else if rps < self.target_rps * 0.5 { self.difficulty = self.difficulty.saturating_sub(1).max(12); }
        self.difficulty
    }
}

// ── Helpers ───────────────────────────────────────────────────────────

fn leading_zeros(hash: &[u8]) -> usize {
    let mut n = 0;
    for &b in hash {
        let z = b.leading_zeros() as usize;
        n += z;
        if z < 8 { break; }
    }
    n
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intro_puzzle_solve_verify() {
        let p   = IntroPuzzle::generate(10);
        let sol = p.solve().unwrap();
        assert!(p.verify(&sol));
    }

    #[test]
    fn intro_puzzle_wrong_nonce() {
        let p = IntroPuzzle::generate(10);
        let mut sol = p.solve().unwrap();
        sol.nonce += 1;
        assert!(!p.verify(&sol));
    }

    #[test]
    fn controller_adjusts() {
        let mut c = PuzzleController::new(10.0);
        let init  = c.difficulty;
        for _ in 0..500 { c.record_request(); }
        assert!(c.difficulty > init);
    }
}

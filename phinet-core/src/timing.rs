// phinet-core/src/timing.rs
//! Constant-time comparison primitives and timing-attack defenses.
//!
//! This module exists so every place in PHINET that compares
//! cryptographic material does so with guaranteed constant-time
//! semantics. Native `==` on byte slices short-circuits on first
//! mismatch — a timing attacker can correlate the response time
//! with which byte differs and recover secrets byte-by-byte.
//!
//! All functions here are wrappers over the `subtle` crate, which
//! implements these primitives with compiler-fence and black-box
//! techniques audited by the RustCrypto team.
//!
//! # What to compare constant-time vs. not
//!
//! Compare **constant-time**:
//! - Authentication tags (HMAC, Poly1305)
//! - Message authentication codes
//! - Secret key bytes
//! - Any value an attacker can influence the other side of
//!   (including derived verify-key outputs)
//!
//! Compare **normal `==`**:
//! - Public identifiers (node_ids seen by the whole network)
//! - Length fields, version numbers
//! - Data already in the public record
//!
//! # Example
//!
//! ```
//! use phinet_core::timing::ct_eq_32;
//!
//! let expected = [0u8; 32];
//! let received = [0u8; 32];
//! if ct_eq_32(&expected, &received) { /* authenticated */ }
//! ```

use subtle::ConstantTimeEq;

/// Constant-time equality of two fixed-size 32-byte arrays. The
/// canonical size for HMAC-SHA256 tags, Poly1305 tags, X25519 keys,
/// node IDs, and our internal verify tags.
pub fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}

/// Constant-time equality of arbitrary byte slices. Returns false if
/// lengths differ (length is not secret). Use this when comparing
/// dynamically-sized authentication tags or MAC outputs.
pub fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    a.ct_eq(b).into()
}

/// Constant-time equality of two 16-byte arrays. Used for Poly1305
/// tag comparison and other 128-bit MAC outputs.
pub fn ct_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    a.ct_eq(b).into()
}

/// Constant-time equality of two 20-byte arrays. Used for
/// rendezvous cookies — the whole point of a cookie is to prevent
/// an attacker from brute-forcing the match.
pub fn ct_eq_20(a: &[u8; 20], b: &[u8; 20]) -> bool {
    a.ct_eq(b).into()
}

/// Constant-time equality of two 64-byte arrays. Used for some
/// full-SHA-512 and double-length MAC outputs.
pub fn ct_eq_64(a: &[u8; 64], b: &[u8; 64]) -> bool {
    a.ct_eq(b).into()
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_32_equal() {
        let a = [0x42u8; 32];
        let b = [0x42u8; 32];
        assert!(ct_eq_32(&a, &b));
    }

    #[test]
    fn ct_eq_32_differ_first_byte() {
        let a = [0x42u8; 32];
        let mut b = a;
        b[0] ^= 1;
        assert!(!ct_eq_32(&a, &b));
    }

    #[test]
    fn ct_eq_32_differ_last_byte() {
        let a = [0x42u8; 32];
        let mut b = a;
        b[31] ^= 1;
        assert!(!ct_eq_32(&a, &b));
    }

    #[test]
    fn ct_eq_bytes_length_mismatch() {
        assert!(!ct_eq_bytes(&[0u8; 8], &[0u8; 7]));
        assert!(!ct_eq_bytes(&[0u8; 7], &[0u8; 8]));
        assert!(ct_eq_bytes(&[0u8; 8], &[0u8; 8]));
    }

    #[test]
    fn ct_eq_bytes_different_content() {
        let a = b"hello_world_1234";
        let b = b"hello_world_1234";
        assert!(ct_eq_bytes(a, b));

        let c = b"Hello_world_1234"; // case diff in first byte
        assert!(!ct_eq_bytes(a, c));
    }

    #[test]
    fn ct_eq_16_equal() {
        assert!(ct_eq_16(&[0xABu8; 16], &[0xABu8; 16]));
    }

    #[test]
    fn ct_eq_16_differ() {
        let a = [0xABu8; 16];
        let mut b = a;
        b[15] ^= 0xFF;
        assert!(!ct_eq_16(&a, &b));
    }

    #[test]
    fn ct_eq_20_cookies() {
        let cookie_a = [0x11u8; 20];
        let cookie_b = [0x11u8; 20];
        assert!(ct_eq_20(&cookie_a, &cookie_b));

        let mut cookie_c = cookie_a;
        cookie_c[10] = 0x22;
        assert!(!ct_eq_20(&cookie_a, &cookie_c));
    }

    #[test]
    fn ct_eq_64_equal_and_differ() {
        let a = [0x7Fu8; 64];
        let b = [0x7Fu8; 64];
        assert!(ct_eq_64(&a, &b));
        let mut c = a;
        c[32] ^= 1;
        assert!(!ct_eq_64(&a, &c));
    }

    #[test]
    fn empty_slices_equal() {
        assert!(ct_eq_bytes(&[], &[]));
    }

    #[test]
    fn all_zeros_vs_all_ones() {
        let zeros = [0u8; 32];
        let ones  = [0xFFu8; 32];
        assert!(!ct_eq_32(&zeros, &ones));
    }

    // ── Timing-variance regression test ───────────────────────────────
    //
    // This test verifies that `ct_eq_32` doesn't short-circuit on first
    // mismatch. It measures the number of CPU cycles (via
    // `std::time::Instant`) for comparisons where the mismatch is at
    // byte 0 vs byte 31, repeats many times, and asserts the means are
    // close (within a tolerance that accounts for scheduler noise).
    //
    // A naive `==` on byte arrays WOULD short-circuit and show a
    // measurable timing difference here. `subtle::ConstantTimeEq`
    // must NOT.
    //
    // This is a smoke test, not a formal timing-side-channel proof.
    // A real adversarial test requires specialized hardware (e.g.
    // `perf` counters, cycle-accurate measurement on an isolated
    // core), but this catches the most common mistake: a regression
    // that reintroduces native equality.

    #[test]
    fn timing_variance_ct_eq_32_no_early_exit() {
        use std::time::Instant;
        const ITERS: usize = 50_000;

        // Baseline: reference, and two candidates differing at either
        // the first or last byte.
        let reference = [0xAAu8; 32];
        let mut diff_first = reference; diff_first[0]  ^= 0xFF;
        let mut diff_last  = reference; diff_last[31]  ^= 0xFF;

        // Warm up the CPU cache and branch predictor to reduce noise.
        for _ in 0..ITERS / 10 {
            let _ = ct_eq_32(&reference, &diff_first);
            let _ = ct_eq_32(&reference, &diff_last);
        }

        let start_first = Instant::now();
        for _ in 0..ITERS {
            // std::hint::black_box prevents the compiler from
            // optimizing the loop away.
            let r = ct_eq_32(&reference, &diff_first);
            std::hint::black_box(r);
        }
        let elapsed_first = start_first.elapsed();

        let start_last = Instant::now();
        for _ in 0..ITERS {
            let r = ct_eq_32(&reference, &diff_last);
            std::hint::black_box(r);
        }
        let elapsed_last = start_last.elapsed();

        // Compute ratio. Both should be within 3x of each other.
        // A short-circuiting `==` would typically show 10-30x ratio
        // between first-byte-mismatch and last-byte-mismatch.
        let ns_first = elapsed_first.as_nanos() as f64;
        let ns_last  = elapsed_last.as_nanos() as f64;
        let ratio    = (ns_first.max(ns_last)) / (ns_first.min(ns_last));

        // Generous tolerance — this runs on shared CI hosts. We just
        // need to catch gross regressions (ratio > 5).
        assert!(
            ratio < 5.0,
            "timing ratio {:.2} suggests short-circuit behavior \
             (first-byte-diff: {}ns, last-byte-diff: {}ns over {} iters)",
            ratio, ns_first as u64, ns_last as u64, ITERS
        );
    }
}

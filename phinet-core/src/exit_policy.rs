// phinet-core/src/exit_policy.rs
//! Exit policy: rules deciding which destinations an exit will open.
//!
//! Without these rules, an exit is a reflector that can be abused to:
//!   * Port-scan or DoS arbitrary internet hosts from the exit's IP
//!   * Reach the exit operator's own internal network (SSRF)
//!   * Reach other tenants on shared hosting
//!   * Hit localhost services (Redis, Postgres, admin panels)
//!
//! # Policy order
//!
//! 1. If the destination is an **IP address** that's in a blocked range
//!    (loopback, link-local, multicast, RFC1918 private, carrier-grade
//!    NAT, reserved), reject unconditionally.
//! 2. If the port is in the block list (by default: 22, 25, 465, 587,
//!    3306, 5432, 6379, 11211, 27017 — SSH/mail/db/cache), reject.
//! 3. Otherwise accept.
//!
//! DNS hostnames aren't resolved here — resolution happens at the TCP
//! layer. An attacker could give us "mail.example.com" which resolves
//! to 127.0.0.1. Defense: after resolution we re-check the connected
//! peer address against the IP blocklist. See `check_post_resolve`.
//!
//! # Non-goals
//!
//! * Full Tor-style exit policy DSL. A single centralized policy fits
//!   the current threat model; operators can edit this file if they
//!   want a different stance.
//! * Domain blocklists (e.g. copyright-enforcement requests). Out of
//!   scope — the exit is supposed to be neutral.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Default ports that an exit refuses for abuse-prevention reasons.
/// The choice mirrors Tor's reduced-exit policy.
pub const DEFAULT_BLOCKED_PORTS: &[u16] = &[
    22,     // SSH — brute force target
    25,     // SMTP — spam relay
    465,    // SMTPS
    587,    // SMTP submission
    110,    // POP3
    143,    // IMAP
    993,    // IMAPS
    995,    // POP3S
    3306,   // MySQL
    5432,   // Postgres
    6379,   // Redis
    11211,  // Memcached
    27017,  // MongoDB
    9200,   // Elasticsearch
];

/// Policy decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Accept,
    Reject,
}

/// Exit policy state. Default constructor builds a reasonable
/// restrictive policy. Operators who want a different stance can
/// edit the blocked_ports list.
pub struct ExitPolicy {
    pub blocked_ports: Vec<u16>,
    /// If true (default), refuse any connection to a private/reserved
    /// IP address. Disabling this is only appropriate for a deliberately
    /// unrestricted local-only test deployment.
    pub block_private: bool,
}

impl Default for ExitPolicy {
    fn default() -> Self {
        Self {
            blocked_ports: DEFAULT_BLOCKED_PORTS.to_vec(),
            block_private: true,
        }
    }
}

impl ExitPolicy {
    /// A policy that accepts everything. Intended for test deployments
    /// where the loopback interface is the only available target.
    /// Production exits should use [`ExitPolicy::default`] which
    /// blocks private ranges and abuse-prone ports.
    pub fn permissive() -> Self {
        Self { blocked_ports: vec![], block_private: false }
    }

    /// Pre-resolve check. `target` is the "host:port" string from
    /// RELAY_BEGIN. Host may be either a hostname, an IPv4 address,
    /// or an IPv6 address in bracket notation `[addr]:port`. Ports
    /// are checked unconditionally; IPs are checked against the
    /// private-range blocklist when `block_private` is set.
    pub fn check_pre_resolve(&self, target: &str) -> Decision {
        let (host, port_str) = if let Some(rest) = target.strip_prefix('[') {
            // IPv6 bracket notation: [addr]:port
            let Some(close) = rest.find(']') else { return Decision::Reject; };
            let host = &rest[..close];
            let after = &rest[close + 1..];
            let Some(port_str) = after.strip_prefix(':') else { return Decision::Reject; };
            (host, port_str)
        } else {
            let Some((h, p)) = target.rsplit_once(':') else {
                return Decision::Reject;
            };
            (h, p)
        };
        let Ok(port): std::result::Result<u16, _> = port_str.parse() else {
            return Decision::Reject;
        };
        if self.blocked_ports.contains(&port) {
            return Decision::Reject;
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            if self.block_private && is_private(&ip) {
                return Decision::Reject;
            }
        }
        Decision::Accept
    }

    /// Post-resolve check. Called once TCP connect has established
    /// the peer address. Blocks sneak-attacks where a hostname was
    /// used to hide a private IP.
    pub fn check_post_resolve(&self, peer: &SocketAddr) -> Decision {
        if self.blocked_ports.contains(&peer.port()) {
            return Decision::Reject;
        }
        if self.block_private && is_private(&peer.ip()) {
            return Decision::Reject;
        }
        Decision::Accept
    }
}

/// True if `ip` is loopback, link-local, multicast, broadcast,
/// private (RFC1918/ULA), or otherwise reserved. Covers both v4 and v6.
pub fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

fn is_private_v4(ip: &Ipv4Addr) -> bool {
    if ip.is_loopback()     { return true; }   // 127.0.0.0/8
    if ip.is_private()      { return true; }   // RFC1918: 10/8, 172.16/12, 192.168/16
    if ip.is_link_local()   { return true; }   // 169.254/16
    if ip.is_multicast()    { return true; }   // 224/4
    if ip.is_broadcast()    { return true; }   // 255.255.255.255
    if ip.is_documentation(){ return true; }   // 192.0.2, 198.51.100, 203.0.113
    if ip.is_unspecified()  { return true; }   // 0.0.0.0

    let octets = ip.octets();
    // Carrier-grade NAT: 100.64.0.0/10
    if octets[0] == 100 && (octets[1] & 0xC0) == 64 { return true; }
    // Benchmark: 198.18.0.0/15
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) { return true; }
    // Reserved class E: 240/4
    if (octets[0] & 0xF0) == 0xF0 { return true; }

    false
}

fn is_private_v6(ip: &Ipv6Addr) -> bool {
    if ip.is_loopback()    { return true; } // ::1
    if ip.is_multicast()   { return true; } // ff00::/8
    if ip.is_unspecified() { return true; } // ::

    let seg = ip.segments();
    // Unique Local Address: fc00::/7
    if (seg[0] & 0xFE00) == 0xFC00 { return true; }
    // Link-local: fe80::/10
    if (seg[0] & 0xFFC0) == 0xFE80 { return true; }
    // IPv4-mapped: ::ffff:0:0/96 — check the embedded v4.
    if seg[0] == 0 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0
        && seg[4] == 0 && seg[5] == 0xFFFF
    {
        let v4 = Ipv4Addr::new(
            (seg[6] >> 8) as u8, (seg[6] & 0xFF) as u8,
            (seg[7] >> 8) as u8, (seg[7] & 0xFF) as u8,
        );
        return is_private_v4(&v4);
    }
    // Documentation: 2001:db8::/32
    if seg[0] == 0x2001 && seg[1] == 0x0DB8 { return true; }

    false
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn loopback_rejected() {
        let p = ExitPolicy::default();
        assert_eq!(p.check_pre_resolve("127.0.0.1:80"), Decision::Reject);
        assert_eq!(p.check_pre_resolve("[::1]:80"), Decision::Reject);
    }

    #[test]
    fn rfc1918_rejected() {
        let p = ExitPolicy::default();
        for target in &["10.0.0.1:80", "192.168.1.1:80", "172.16.0.1:80",
                        "172.20.1.1:80", "172.31.255.254:80"] {
            assert_eq!(p.check_pre_resolve(target), Decision::Reject,
                       "should reject {}", target);
        }
    }

    #[test]
    fn link_local_rejected() {
        let p = ExitPolicy::default();
        assert_eq!(p.check_pre_resolve("169.254.1.1:80"), Decision::Reject);
    }

    #[test]
    fn carrier_grade_nat_rejected() {
        let p = ExitPolicy::default();
        // 100.64.0.0/10 = CGN
        assert_eq!(p.check_pre_resolve("100.64.0.1:80"), Decision::Reject);
        assert_eq!(p.check_pre_resolve("100.127.255.254:80"), Decision::Reject);
    }

    #[test]
    fn global_ip_accepted() {
        let p = ExitPolicy::default();
        assert_eq!(p.check_pre_resolve("8.8.8.8:443"), Decision::Accept);
        assert_eq!(p.check_pre_resolve("1.1.1.1:443"), Decision::Accept);
    }

    #[test]
    fn blocked_ports_rejected() {
        let p = ExitPolicy::default();
        for port in &[22u16, 25, 3306, 5432, 6379] {
            let t = format!("8.8.8.8:{}", port);
            assert_eq!(p.check_pre_resolve(&t), Decision::Reject,
                       "should reject port {}", port);
        }
    }

    #[test]
    fn normal_web_ports_accepted() {
        let p = ExitPolicy::default();
        for port in &[80u16, 443, 8080, 8443] {
            let t = format!("8.8.8.8:{}", port);
            assert_eq!(p.check_pre_resolve(&t), Decision::Accept);
        }
    }

    #[test]
    fn malformed_target_rejected() {
        let p = ExitPolicy::default();
        assert_eq!(p.check_pre_resolve("no-port"),            Decision::Reject);
        assert_eq!(p.check_pre_resolve("host:notaport"),      Decision::Reject);
        assert_eq!(p.check_pre_resolve(""),                    Decision::Reject);
        assert_eq!(p.check_pre_resolve(":80"),                 Decision::Accept);  // empty host isn't an IP; we let TCP fail it
    }

    #[test]
    fn hostname_defers_to_post_resolve() {
        let p = ExitPolicy::default();
        // Hostnames pass the pre-resolve check (port is fine).
        assert_eq!(p.check_pre_resolve("example.com:80"), Decision::Accept);
        assert_eq!(p.check_pre_resolve("my.internal.company.net:80"), Decision::Accept);
    }

    #[test]
    fn post_resolve_blocks_sneaky_dns() {
        let p = ExitPolicy::default();
        // Attacker crafted a hostname that resolved to 127.0.0.1
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80);
        assert_eq!(p.check_post_resolve(&peer), Decision::Reject);
    }

    #[test]
    fn post_resolve_blocks_rfc1918_after_resolve() {
        let p = ExitPolicy::default();
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10,0,0,5)), 443);
        assert_eq!(p.check_post_resolve(&peer), Decision::Reject);
    }

    #[test]
    fn post_resolve_accepts_global() {
        let p = ExitPolicy::default();
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8,8,8,8)), 443);
        assert_eq!(p.check_post_resolve(&peer), Decision::Accept);
    }

    #[test]
    fn ipv6_ula_rejected() {
        let p = ExitPolicy::default();
        assert_eq!(p.check_pre_resolve("[fc00::1]:80"), Decision::Reject);
        assert_eq!(p.check_pre_resolve("[fd12:3456::1]:80"), Decision::Reject);
    }

    #[test]
    fn ipv6_link_local_rejected() {
        let p = ExitPolicy::default();
        assert_eq!(p.check_pre_resolve("[fe80::1]:80"), Decision::Reject);
    }

    #[test]
    fn ipv6_global_accepted() {
        let p = ExitPolicy::default();
        assert_eq!(p.check_pre_resolve("[2606:4700:4700::1111]:443"), Decision::Accept);
    }

    #[test]
    fn ipv4_mapped_in_ipv6_rejected() {
        // ::ffff:127.0.0.1 → still loopback
        let ipv6 = Ipv6Addr::new(0,0,0,0,0,0xFFFF,0x7F00,0x0001);
        let ip   = IpAddr::V6(ipv6);
        assert!(is_private(&ip));
    }

    #[test]
    fn permissive_accepts_everything() {
        let p = ExitPolicy::permissive();
        assert_eq!(p.check_pre_resolve("127.0.0.1:22"), Decision::Accept);
        assert_eq!(p.check_pre_resolve("10.0.0.1:3306"), Decision::Accept);
    }

    #[test]
    fn documentation_ranges_rejected() {
        let p = ExitPolicy::default();
        // RFC5737 documentation ranges shouldn't receive traffic
        assert_eq!(p.check_pre_resolve("192.0.2.1:80"),    Decision::Reject);
        assert_eq!(p.check_pre_resolve("198.51.100.1:80"), Decision::Reject);
        assert_eq!(p.check_pre_resolve("203.0.113.1:80"),  Decision::Reject);
    }

    #[test]
    fn class_e_reserved_rejected() {
        let p = ExitPolicy::default();
        assert_eq!(p.check_pre_resolve("240.0.0.1:80"),  Decision::Reject);
        assert_eq!(p.check_pre_resolve("255.0.0.1:80"),  Decision::Reject);
    }

    #[test]
    fn unspecified_addresses_rejected() {
        let p = ExitPolicy::default();
        assert_eq!(p.check_pre_resolve("0.0.0.0:80"), Decision::Reject);
        assert_eq!(p.check_pre_resolve("[::]:80"),    Decision::Reject);
    }
}

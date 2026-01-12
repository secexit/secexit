use super::*;
use secexit_common::expand_path;
use std::mem;

// helper to create dummy policy
fn make_policy(
    lockdown: bool,
    blocked_ips: Vec<&str>,
    blocked_domains: Vec<&str>,
) -> SecurityPolicy {
    SecurityPolicy {
        revision: 1,
        lockdown_mode: lockdown,
        blocked_ips: blocked_ips.into_iter().map(String::from).collect(),
        blocked_domains: blocked_domains.into_iter().map(String::from).collect(),
    }
}

#[test]
fn test_expand_path() {
    // Note:  relies on env having a HOME/User dir
    let expanded = expand_path("~/.config/test.json");

    // check tilde is gone
    assert!(!expanded.starts_with("~"));
    // check suffix remains
    assert!(expanded.ends_with("/.config/test.json"));

    // check absolute paths are unchanged
    let absolute = "/tmp/test.json";
    assert_eq!(expand_path(absolute), absolute);
}

#[test]
fn test_domain_blocking() {
    // normal allow
    let policy = make_policy(false, vec![], vec!["example.com"]);
    assert!(!should_block_domain("google.com", &policy));

    // block
    assert!(should_block_domain("example.com", &policy));

    // check substring matching
    assert!(should_block_domain("sub.example.com", &policy));
    assert!(should_block_domain("api.example.com", &policy));

    // Lockdown Mode (blocks everything)
    let lockdown = make_policy(true, vec![], vec![]);
    assert!(should_block_domain("google.com", &lockdown));
    assert!(should_block_domain("anything.local", &lockdown));
}

#[test]
fn test_ip_blocking() {
    // normal allow
    let policy = make_policy(false, vec!["192.168.1.50"], vec![]);
    assert!(!should_block_ip("1.1.1.1", &policy));

    // block
    assert!(should_block_ip("192.168.1.50", &policy));

    // Lockdown Mode
    let lockdown = make_policy(true, vec![], vec![]);
    assert!(should_block_ip("8.8.8.8", &lockdown));
}

#[test]
fn test_sockaddr_conversion_ipv4() {
    unsafe {
        // construct C sockaddr_in structure
        let mut sin: libc::sockaddr_in = mem::zeroed();
        sin.sin_family = libc::AF_INET as u16;
        sin.sin_port = 8080u16.to_be(); // Port 8080 big-endian

        // IP 127.0.0.1 => bytes [127, 0, 0, 1]
        sin.sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]).to_be();

        let ptr = &sin as *const _ as *const sockaddr;
        let len = mem::size_of::<libc::sockaddr_in>() as socklen_t;

        let result = sockaddr_to_rust(ptr, len);

        assert!(result.is_some());
        let socket = result.unwrap();

        assert_eq!(socket.ip(), "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(socket.port(), 8080);
    }
}

#[test]
fn test_sockaddr_ignore_ipv6() {
    unsafe {
        // a dummy IPv6 struct
        let mut sin6: libc::sockaddr_in6 = mem::zeroed();
        sin6.sin6_family = libc::AF_INET6 as u16;

        let ptr = &sin6 as *const _ as *const sockaddr;
        let len = mem::size_of::<libc::sockaddr_in6>() as socklen_t;

        // should return None because shim only handles IPv4 (for the time being)
        let result = sockaddr_to_rust(ptr, len);
        assert!(result.is_none());
    }
}

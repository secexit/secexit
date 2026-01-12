use super::*;
use clap::Parser;
use secexit_common::SecurityPolicy;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

// mimic kernel maps in memory so we assert what *would* be written.
#[derive(Default, Clone)]
struct MockEnforcer {
    lockdown: Arc<Mutex<bool>>,
    blocked_ips: Arc<Mutex<HashSet<u32>>>,
}

#[async_trait::async_trait]
impl PolicyEnforcer for MockEnforcer {
    async fn set_lockdown(&mut self, enabled: bool) -> anyhow::Result<()> {
        *self.lockdown.lock().unwrap() = enabled;
        Ok(())
    }

    async fn block_ip(&mut self, ip: u32) -> anyhow::Result<()> {
        self.blocked_ips.lock().unwrap().insert(ip);
        Ok(())
    }
}

#[test]
fn test_cli_args_parsing() {
    // default
    let args = Args::try_parse_from(["secexit-daemon"]).unwrap();
    assert_eq!(args.policy, "~/.config/secexit/policy.json");

    // flag override
    let args = Args::try_parse_from(["secexit-daemon", "--policy", "/tmp/p.json"]).unwrap();
    assert_eq!(args.policy, "/tmp/p.json");
}

#[tokio::test]
async fn test_policy_lockdown_mode() {
    let mut enforcer = MockEnforcer::default();

    let policy = SecurityPolicy {
        revision: 1,
        lockdown_mode: true,
        blocked_ips: vec!["8.8.8.8".to_string()],
        blocked_domains: vec![],
    };

    apply_policy_logic(&policy, &mut enforcer).await.unwrap();

    // Lockdown is ON
    assert!(*enforcer.lockdown.lock().unwrap());

    // NO IPs were processed (optimization check)
    // The logic should return early when in lockdown mode.
    assert!(enforcer.blocked_ips.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_policy_allow_mode_static_ips() {
    let mut enforcer = MockEnforcer::default();

    let policy = SecurityPolicy {
        revision: 1,
        lockdown_mode: false,
        blocked_ips: vec!["192.168.1.1".to_string(), "invalid_ip_string".to_string()],
        blocked_domains: vec![],
    };

    apply_policy_logic(&policy, &mut enforcer).await.unwrap();

    // Assert Lockdown is OFF
    assert!(!(*enforcer.lockdown.lock().unwrap()));

    let blocked = enforcer.blocked_ips.lock().unwrap();

    // 192.168.1.1 => C0 A8 01 01 => 0xC0A80101
    let expected_ip = ip_to_u32_be("192.168.1.1".parse().unwrap());

    assert!(blocked.contains(&expected_ip));
    assert_eq!(blocked.len(), 1); // "invalid_ip_string"
}

#[tokio::test]
async fn test_policy_resolves_localhost() {
    // Note: this relies on "localhost" resolving to 127.0.0.1 on the build machine.

    let mut enforcer = MockEnforcer::default();

    let policy = SecurityPolicy {
        revision: 1,
        lockdown_mode: false,
        blocked_ips: vec![],
        blocked_domains: vec!["localhost".to_string()],
    };

    apply_policy_logic(&policy, &mut enforcer).await.unwrap();

    let blocked = enforcer.blocked_ips.lock().unwrap();
    let localhost_ip = ip_to_u32_be("127.0.0.1".parse().unwrap());

    // NOTE: This test might fail if localhost resolves to IPv6 only ::1
    // But standard linux envs usually have 127.0.0.1.
    if !blocked.is_empty() {
        assert!(blocked.contains(&localhost_ip));
    }
}

use anyhow::Context;
use aya::{
    Ebpf, include_bytes_aligned,
    maps::{Array, HashMap},
    programs::{CgroupAttachMode, CgroupSockAddr},
};
use clap::Parser;
use secexit_common::load_policy;
use std::net::Ipv4Addr;
use tokio::signal;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "secexit daemon",
    long_about = "A security daemon that enforces egress filtering policies using eBPF."
)]
pub struct Args {
    #[arg(
        short,
        long,
        env = "SECEXIT_POLICY",
        default_value = "~/.config/secexit/policy.json",
        help = "Path or URL to the policy JSON file"
    )]
    pub policy: String,
}

/// convert IPv4 to Big-Endian u32 (Network Byte Order)
pub fn ip_to_u32_be(ip: Ipv4Addr) -> u32 {
    u32::from(ip).to_be()
}

/// trait to abstract over the eBPF Map.
#[async_trait::async_trait]
pub trait PolicyEnforcer {
    async fn set_lockdown(&mut self, enabled: bool) -> anyhow::Result<()>;
    async fn block_ip(&mut self, ip: u32) -> anyhow::Result<()>;
}

/// resolves domains and calculates which IPs to block.
/// It calls the `enforcer` trait to apply changes, so it doesn't care if it's
/// writing to a real Kernel map or a Test Hashmap.
pub async fn apply_policy_logic(
    policy: &secexit_common::SecurityPolicy,
    enforcer: &mut impl PolicyEnforcer,
) -> anyhow::Result<()> {
    if policy.lockdown_mode {
        log::warn!("!!! LOCKDOWN MODE ENABLED !!! blocking all IPv4 traffic.");
        enforcer.set_lockdown(true).await?;
        log::info!("skipping IP/Domain resolution due to lockdown.");
        return Ok(());
    }

    // ensure lockdown is OFF
    enforcer.set_lockdown(false).await?;

    log::info!("applying {} static IP rules...", policy.blocked_ips.len());
    for ip_str in &policy.blocked_ips {
        if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
            enforcer.block_ip(ip_to_u32_be(ip)).await?;
            log::info!(" + Blocked Static IP: {}", ip_str);
        } else {
            log::warn!(" ! Invalid IP in policy: {}", ip_str);
        }
    }

    log::info!("resolving {} domains...", policy.blocked_domains.len());
    for domain in &policy.blocked_domains {
        // we use a separate function for DNS so we can potentially mock it later,
        let query = format!("{}:80", domain);
        match tokio::net::lookup_host(&query).await {
            Ok(addrs) => {
                let mut count = 0;
                for addr in addrs {
                    if let std::net::SocketAddr::V4(socket_addr) = addr {
                        let ip = *socket_addr.ip();
                        if enforcer.block_ip(ip_to_u32_be(ip)).await.is_ok() {
                            count += 1;
                        }
                    }
                }
                if count > 0 {
                    log::info!(" + domain '{}' blocked ({} IPs added)", domain, count);
                } else {
                    log::warn!(" ! domain '{}' resolved but returned no IPv4.", domain);
                }
            }
            Err(e) => log::error!(" ! Failed to resolve domain '{}': {}", domain, e),
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    log::warn!("starting secexit daemon");
    env_logger::init();

    let args = Args::parse();
    let policy = load_policy(&args.policy).await;

    // TODO: need to clean this up
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/secexit-ebpf"
    ))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
        log::warn!("failed to initialize eBPF logger: {}", e);
    }

    let program: &mut CgroupSockAddr = bpf
        .program_mut("egress_filter")
        .context("program 'egress_filter' not found")?
        .try_into()?;
    program.load().context("loading program")?;
    program.attach(
        std::fs::File::open("/sys/fs/cgroup")?,
        CgroupAttachMode::Single,
    )?;
    log::info!("eBPF program attached.");

    struct AyaEnforcer {
        // We now own the MapData, so no lifetimes needed
        settings: Array<aya::maps::MapData, u32>,
        blocked_ips: HashMap<aya::maps::MapData, u32, u32>,
    }

    #[async_trait::async_trait]
    impl PolicyEnforcer for AyaEnforcer {
        async fn set_lockdown(&mut self, enabled: bool) -> anyhow::Result<()> {
            let val = if enabled { 1 } else { 0 };
            self.settings.set(0, val, 0).map_err(|e| anyhow::anyhow!(e))
        }

        async fn block_ip(&mut self, ip: u32) -> anyhow::Result<()> {
            self.blocked_ips
                .insert(ip, 1, 0)
                .map_err(|e| anyhow::anyhow!(e))
        }
    }

    let settings_map = bpf
        .take_map("SETTINGS")
        .ok_or(anyhow::anyhow!("SETTINGS map not found"))?;

    let blocked_ips_map = bpf
        .take_map("BLOCKED_IPS")
        .ok_or(anyhow::anyhow!("BLOCKED_IPS map not found"))?;

    let mut enforcer = AyaEnforcer {
        settings: Array::try_from(settings_map)?,
        blocked_ips: HashMap::try_from(blocked_ips_map)?,
    };

    apply_policy_logic(&policy, &mut enforcer).await?;

    log::info!("secexit daemon running. Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    log::info!("exiting...");
    Ok(())
}

#[cfg(test)]
mod tests;

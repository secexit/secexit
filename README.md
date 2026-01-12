# secexit

**secexit** blocks unauthorized outbound traffic from your servers using eBPF.

_Zero config. Zero latency. Zero trust._

secexit is designed to strictly control egress (outbound) network traffic on Linux systems. It uses kernel-space enforcement (eBPF) for unbypassable IP-based blocking.

This architecture ensures that even if an application bypasses the DNS filter (e.g., by using a static binary or hardcoded IPs), the kernel-level eBPF filter will catch and drop the traffic.

## Quickstart

### 1. Define Policy

Create a policy file at `~/.config/secexit/policy.json`. You can also provide an HTTP URL to the daemon later.

```json
{
  "revision": 1,
  "lockdown_mode": false,
  "blocked_domains": [
    "www.google.com",
  ],
  "blocked_ips": [
    "1.1.1.1",
  ]
}

```

Use `SECEXIT_POLICY` env var to set a different path to this file.

### 2. Run the Daemon (eBPF Filter)

The daemon loads the eBPF program into the kernel. It requires `root` to attach to the cgroup hooks.

**Run via Cargo:**

```bash
sudo RUST_LOG=info cargo run --release --bin secexit-daemon

```

**Or run the binary directly:**

```bash
sudo RUST_LOG=info ./target/release/secexit-daemon

```

**Output:**

```text
[INFO  secexit_common] secexit policy (v1) loaded from: /root/.config/secexit/policy.json
[INFO  secexit_daemon] eBPF program attached.
[INFO  secexit_daemon] applying 0 static IP rules...
[INFO  secexit_daemon] resolving 1 domains...
[INFO  secexit_daemon]  + domain '[www.google.com](https://www.google.com)' blocked (1 IPs added)
[INFO  secexit_daemon] secexit daemon running. Waiting for Ctrl-C...

```

### 3. Check its working

Once the daemon is running, the kernel will drop packets destined for blocked IPs.

**Test with curl:**

```bash
curl [https://www.google.com](https://www.google.com) -v

```

**Expected Result:**

```text
* Host [www.google.com:443](https://www.google.com:443) was resolved.
* IPv4: 142.251.141.164
* Trying 142.251.141.164:443...
* Immediate connect fail for 142.251.141.164: Operation not permitted
curl: (7) Failed to connect to [www.google.com](https://www.google.com) port 443: Operation not permitted

```

**Test with ping:**

```bash
ping [www.google.com](https://www.google.com)
# Output: ping: connect: Operation not permitted

```

*Note: Since eBPF requires IP addresses, the daemon resolves the domains defined in your policy at startup and pushes the resulting IPs to the kernel blocklist.*

### Optional: Userspace Shim

If you cannot use eBPF or want to block DNS resolution in userspace (Layer 7), use `LD_PRELOAD`. This reads the same `policy.json` but hooks `getaddrinfo`.

```bash
LD_PRELOAD=./target/release/libsecexit_shim.so curl [https://www.google.com](https://www.google.com) -v

```

**Output:**

```text
[secexit] BLOCKED DOMAIN: [www.google.com](https://www.google.com)
curl: (6) Could not resolve host: [www.google.com](https://www.google.com)

```

## Architecture

The project consists of three main components:

**1. `secexit-ebpf` (Kernel Space / Layer 3)**
An eBPF program attached to the cgroup `connect4` hook. It inspects every IPv4 TCP/UDP connection attempt directly at the kernel level. It enforces specific IP blocks or a global "Lockdown Mode" (kill switch). It cannot be bypassed by userspace applications, even static Go binaries.

**2. `secexit-daemon` (Controller)**
A Rust async daemon (Tokio + Aya) that loads the eBPF program and reads `policy.json`. It performs DNS lookups in the context environment for blocked domains and pushes the resulting IPs to the eBPF map. It also toggles the global kill switch via a shared eBPF map.

**3. `secexit-shim` (Userspace / Layer 7)**
A shared object library used with `LD_PRELOAD`. It hooks `getaddrinfo` to intercept and block DNS requests based on `policy.json`. As this is userspace, it can be bypassed by direct `connect()` calls or custom DNS resolvers.

## Development

### Prerequisites

* **OS:** Linux (Kernel 5.8+ required for full cgroup eBPF support).
* **Rust:** Nightly toolchain (required for building eBPF).
* **Tools:** `bpf-linker`, `cargo-xtask`.

```bash
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker cargo-xtask

```

### Build Process

Order matters. The kernel program must be built before the userspace daemon, as the daemon embeds the resulting ELF binary.

1. **Build eBPF Kernel Program:**
```bash
cargo xtask build-ebpf --release

```


2. **Build Userspace Components:**
```bash
cargo build --release

```



## FAQ

**Why not support globbing of domain names?**
eBPF operates strictly on IP addresses. To block a domain, `secexit-daemon` must resolve it to an IP first. Supporting wildcards (e.g., `*.google.com`) would require scanning the entire DNS space or intercepting all DNS packets in userspace, which significantly increases complexity and latency.

**Error: `Invalid ELF header size**`
You likely built the project for the host architecture (x86_64) instead of BPF. Run `cargo clean` and then explicitly run `cargo xtask build-ebpf --release`.

**Error: `Operation not permitted` (OS Error)**
You are not running the daemon as `sudo`. eBPF operations require root privileges.

**Logs not showing?**
Ensure the environment variable `RUST_LOG=info` is set. For raw kernel logs, check `/sys/kernel/tracing/trace_pipe`.

**What's with the name?**
A nod to mainframe security exits. (No relation to IBM).

```

```
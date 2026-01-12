use clap::Parser;
use lazy_static::lazy_static;
use libc::{addrinfo, c_char, c_int, sockaddr, socklen_t};
use secexit_common::{SecurityPolicy, load_policy};
use std::ffi::CStr;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;

#[derive(Parser, Debug)]
#[command(author, version, about = "secexit shim", long_about = None)]
struct Args {
    #[arg(
        short,
        long,
        env = "SECEXIT_POLICY",
        default_value = "~/.config/secexit/policy.json"
    )]
    policy: String,
}

// return TRUE if domain should be BLOCKED
fn should_block_domain(hostname: &str, policy: &SecurityPolicy) -> bool {
    if policy.lockdown_mode {
        return true;
    }
    for domain in &policy.blocked_domains {
        if hostname.contains(domain) {
            return true;
        }
    }
    false
}

// return TRUE if IP should be BLOCKED
fn should_block_ip(ip_str: &str, policy: &SecurityPolicy) -> bool {
    if policy.lockdown_mode {
        return true;
    }
    for blocked in &policy.blocked_ips {
        if ip_str == blocked {
            return true;
        }
    }
    false
}

lazy_static! {
    static ref POLICY: Mutex<SecurityPolicy> = {
        let final_path = Args::try_parse()
            .map(|a| a.policy)
            .unwrap_or_else(|_| "~/.config/secexit/policy.json".to_string());

        match tokio::runtime::Runtime::new() {
            Ok(rt) => {
                let policy = rt.block_on(load_policy(&final_path));
                Mutex::new(policy)
            }
            Err(e) => {
                eprintln!(
                    "[secexit] ERROR: Failed to create async runtime: {}. Defaulting to ALLOW.",
                    e
                );
                Mutex::new(SecurityPolicy::default_allow())
            }
        }
    };
    static ref REAL_CONNECT: Mutex<Option<ConnectFn>> = Mutex::new(None);
    static ref REAL_GETADDRINFO: Mutex<Option<GetAddrInfoFn>> = Mutex::new(None);
}

type ConnectFn = unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int;
type GetAddrInfoFn = unsafe extern "C" fn(
    *const c_char,
    *const c_char,
    *const addrinfo,
    *mut *mut addrinfo,
) -> c_int;

unsafe fn get_real_connect() -> ConnectFn {
    let mut real = REAL_CONNECT.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(f) = *real {
        return f;
    }
    let sym = c"connect";
    let ptr = unsafe { libc::dlsym(libc::RTLD_NEXT, sym.as_ptr()) };
    let f: ConnectFn = unsafe { std::mem::transmute(ptr) };
    *real = Some(f);
    f
}

unsafe fn get_real_getaddrinfo() -> GetAddrInfoFn {
    let mut real = REAL_GETADDRINFO.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(f) = *real {
        return f;
    }
    let sym = b"getaddrinfo\0";
    let ptr = unsafe { libc::dlsym(libc::RTLD_NEXT, sym.as_ptr() as *const c_char) };
    let f: GetAddrInfoFn = unsafe { std::mem::transmute(ptr) };
    *real = Some(f);
    f
}

/// hook for standard libc `getaddrinfo` function.
///
/// # Safety
///
/// This function is unsafe because it operates on raw C pointers.
/// The caller must ensure that:
/// * `node` and `service` are valid, null-terminated C strings (if provided).
/// * `hints` points to a valid `addrinfo` struct (if provided).
/// * `res` is a valid pointer to a pointer where the result will be stored.
/// * This function is intended to be called by the C runtime (libc).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getaddrinfo(
    node: *const c_char,
    service: *const c_char,
    hints: *const addrinfo,
    res: *mut *mut addrinfo,
) -> c_int {
    if !node.is_null()
        && let Ok(hostname) = unsafe { CStr::from_ptr(node) }.to_str()
    {
        let policy = POLICY.lock().unwrap_or_else(|e| e.into_inner());

        if should_block_domain(hostname, &policy) {
            if policy.lockdown_mode {
                eprintln!("[secexit] LOCKDOWN: Blocking DNS lookup for {}", hostname);
            } else {
                eprintln!("[secexit] BLOCKED DOMAIN: {}", hostname);
            }
            return libc::EAI_FAIL;
        }
    }
    unsafe { get_real_getaddrinfo()(node, service, hints, res) }
}

/// hook for standard libc `getaddrinfo` function.
///
/// # Safety
///
/// This function is unsafe because it operates on raw C pointers.
/// The caller must ensure that:
/// * `node` and `service` are valid, null-terminated C strings (if provided).
/// * `hints` points to a valid `addrinfo` struct (if provided).
/// * `res` is a valid pointer to a pointer where the result will be stored.
/// * This function is intended to be called by the C runtime (libc).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect(
    sockfd: c_int,
    addr: *const sockaddr,
    addrlen: socklen_t,
) -> c_int {
    if let Some(sa) = unsafe { sockaddr_to_rust(addr, addrlen) }
        && let IpAddr::V4(ipv4) = sa.ip()
    {
        let ip_str = ipv4.to_string();
        let policy = POLICY.lock().unwrap_or_else(|e| e.into_inner());

        if should_block_ip(&ip_str, &policy) {
            eprintln!("[secexit] BLOCKED IP: {}", ip_str);
            unsafe { *libc::__errno_location() = libc::EACCES };
            return -1;
        }
    }
    unsafe { get_real_connect()(sockfd, addr, addrlen) }
}

unsafe fn sockaddr_to_rust(addr: *const sockaddr, _len: socklen_t) -> Option<SocketAddr> {
    if addr.is_null() {
        return None;
    }
    let family = unsafe { (*addr).sa_family as i32 };
    if family == libc::AF_INET {
        let sin = unsafe { &*(addr as *const libc::sockaddr_in) };
        let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
        let port = u16::from_be(sin.sin_port);
        return Some(SocketAddr::new(IpAddr::V4(ip), port));
    }
    None
}

#[cfg(test)]
mod tests;

#![no_std]
#![no_main]

mod bindings;
use bindings::AF_INET;

use aya_ebpf::bindings::bpf_sock_addr;

use aya_ebpf::cty::c_long;
use aya_ebpf::{macros::cgroup_sock_addr, programs::SockAddrContext};
use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap},
};
use aya_log_ebpf::warn;

#[map]
static BLOCKED_IPS: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[map]
static SETTINGS: Array<u32> = Array::with_max_entries(1, 0);

#[cgroup_sock_addr(connect4)]
pub fn egress_filter(ctx: SockAddrContext) -> i32 {
    match try_egress_filter(ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // Block on error (fail closed)
    }
}

fn try_egress_filter(ctx: SockAddrContext) -> Result<i32, c_long> {
    // ctx.sock_addr is the *Aya* version of the struct
    let sock: *mut bpf_sock_addr = ctx.sock_addr;

    if sock.is_null() {
        return Ok(0);
    }

    let family = unsafe { (*sock).user_family };
    let dest_ip = unsafe { (*sock).user_ip4 };

    if family != AF_INET as u32 {
        return Ok(1);
    }

    if let Some(lockdown_flag) = SETTINGS.get(0) {
        // if flag is 1, we BLOCK everything 'tout suite'.
        if *lockdown_flag == 1 {
            return Ok(0);
        }
    }

    if unsafe { BLOCKED_IPS.get(&dest_ip) }.is_some() {
        warn!(&ctx, "BLOCKING IP: {:i}", dest_ip); // Warn level
        return Ok(0); // block
    }

    Ok(1) // allow
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

use aya_ebpf::programs::LsmContext;

use crate::{
    emit_deny_event, finish_decision, lookup_caller_zone, read_kernel_u16, read_kernel_u32,
    read_kernel_u64, ZONE_POLICY,
};
use syva_ebpf_common::{
    AF_INET, AF_INET6, HOOK_SOCKET_CONNECT, POLICY_FLAG_ALLOW_EGRESS, PROG_SOCKET_CONNECT,
    ZONE_FLAG_GLOBAL, ZONE_ID_HOST,
};

pub fn socket_connect(ctx: &LsmContext) -> i32 {
    finish_decision(PROG_SOCKET_CONNECT, try_socket_connect(ctx))
}

/// LSM hook: security_socket_connect(struct socket *sock,
///     struct sockaddr *address, int addrlen)
///
/// Egress lock: a non-global zoned caller may not initiate outbound
/// AF_INET/AF_INET6 connections unless its zone policy carries
/// POLICY_FLAG_ALLOW_EGRESS (set for every network mode except Isolated).
/// Loopback is always allowed; AF_UNIX is left to the unix_stream_connect
/// hook; unzoned callers are invisible to enforcement.
#[inline(always)]
fn try_socket_connect(ctx: &LsmContext) -> Result<i32, i64> {
    let caller = match lookup_caller_zone(ctx) {
        Some(info) => info,
        None => return Ok(0),
    };

    if caller.flags & ZONE_FLAG_GLOBAL != 0 {
        return Ok(0);
    }

    // arg(1) = struct sockaddr *address (kernel-copied before the hook).
    let addr_ptr: u64 = unsafe { ctx.arg(1) };
    if addr_ptr == 0 {
        return Ok(0);
    }

    // sa_family is the first u16 of struct sockaddr.
    let family = unsafe { read_kernel_u16(addr_ptr, 0)? };
    if family != AF_INET && family != AF_INET6 {
        // AF_UNIX and everything else: not this hook's concern.
        return Ok(0);
    }

    if unsafe { is_loopback(addr_ptr, family)? } {
        return Ok(0);
    }

    // Egress permitted if the zone policy allows it (mode != Isolated).
    if let Some(policy) = ZONE_POLICY.get(caller.zone_id) {
        if policy.flags & POLICY_FLAG_ALLOW_EGRESS != 0 {
            return Ok(0);
        }
    }

    emit_deny_event(
        HOOK_SOCKET_CONNECT,
        caller.zone_id,
        ZONE_ID_HOST,
        family as u64,
    );
    Ok(-1)
}

/// Loopback detection. The bpfel target is little-endian.
/// IPv4: sockaddr_in.sin_addr at offset 4; 127.0.0.0/8 has high octet 127,
/// which is the low byte of the network-order word read on a LE host.
/// IPv6: sockaddr_in6.sin6_addr at offset 8; ::1 is fifteen zero bytes then
/// 0x01 (the high u64 is 0, the low u64 is 0x0100000000000000 on LE).
#[inline(always)]
unsafe fn is_loopback(addr_ptr: u64, family: u16) -> Result<bool, i64> {
    if family == AF_INET {
        let s_addr = read_kernel_u32(addr_ptr, 4)?;
        return Ok(s_addr & 0xff == 127);
    }
    // AF_INET6
    let hi = read_kernel_u64(addr_ptr, 8)?;
    let lo = read_kernel_u64(addr_ptr, 16)?;
    Ok(hi == 0 && lo == 0x0100_0000_0000_0000)
}

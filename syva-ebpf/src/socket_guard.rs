use aya_ebpf::programs::LsmContext;

use crate::{
    egress_cidr_allows, emit_deny_event, finish_decision, lookup_caller_zone, read_kernel_u16,
    read_kernel_u32, read_kernel_u64, ZONE_POLICY,
};
use syva_ebpf_common::{
    AF_INET, AF_INET6, HOOK_SOCKET_BIND, HOOK_SOCKET_CONNECT, HOOK_SOCKET_SENDMSG,
    POLICY_FLAG_ALLOW_NETWORK, PROG_SOCKET_BIND, PROG_SOCKET_CONNECT, PROG_SOCKET_SENDMSG,
    ZONE_FLAG_GLOBAL, ZONE_ID_HOST,
};

// --- Three network hooks, one decision shape ---
//
// An Isolated zone (no POLICY_FLAG_ALLOW_NETWORK) is network-isolated: it may
// talk to loopback only. These hooks deny its non-loopback AF_INET/AF_INET6
// operations and let everything else (loopback, non-IP families, unzoned
// callers, network-allowed zones) through. AF_UNIX stream connects stay with
// the dedicated unix_stream_connect hook.

/// LSM `socket_connect(struct socket *sock, struct sockaddr *address, int)`.
/// Outbound connect — covers TCP and connected UDP.
pub fn socket_connect(ctx: &LsmContext) -> i32 {
    finish_decision(
        PROG_SOCKET_CONNECT,
        gate_addr_arg(ctx, 1, HOOK_SOCKET_CONNECT, true),
    )
}

/// LSM `socket_bind(struct socket *sock, struct sockaddr *address, int)`.
/// Inbound listener — denying non-loopback bind stops an isolated zone from
/// exposing a service on the network (and therefore from accepting from it).
/// `bind` governs the LOCAL address, so the egress CIDR allowlist never applies.
pub fn socket_bind(ctx: &LsmContext) -> i32 {
    finish_decision(
        PROG_SOCKET_BIND,
        gate_addr_arg(ctx, 1, HOOK_SOCKET_BIND, false),
    )
}

/// LSM `socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)`.
/// Outbound datagram — covers UNCONNECTED UDP (sendto/sendmsg), which never
/// calls connect() and so bypasses socket_connect entirely.
pub fn socket_sendmsg(ctx: &LsmContext) -> i32 {
    finish_decision(PROG_SOCKET_SENDMSG, try_sendmsg(ctx))
}

/// Shared gate for hooks whose argument `arg_idx` is a `struct sockaddr *`.
/// `egress` enables the per-zone CIDR allowlist (connect/sendmsg only).
#[inline(always)]
fn gate_addr_arg(ctx: &LsmContext, arg_idx: usize, hook: u8, egress: bool) -> Result<i32, i64> {
    let Some(caller) = network_locked_caller(ctx) else {
        return Ok(0);
    };
    let addr_ptr: u64 = unsafe { ctx.arg(arg_idx) };
    gate_remote(addr_ptr, caller, hook, egress)
}

#[inline(always)]
fn try_sendmsg(ctx: &LsmContext) -> Result<i32, i64> {
    let Some(caller) = network_locked_caller(ctx) else {
        return Ok(0);
    };
    // arg(1) = struct msghdr *. msg_name (the destination sockaddr) is the
    // first field (offset 0); it is NULL for connected sockets, where the
    // connect() hook already governed the peer.
    let msg_ptr: u64 = unsafe { ctx.arg(1) };
    if msg_ptr == 0 {
        return Ok(0);
    }
    let addr_ptr = unsafe { read_kernel_u64(msg_ptr, 0)? };
    gate_remote(addr_ptr, caller, HOOK_SOCKET_SENDMSG, true)
}

/// Returns the caller's zone id only when the caller is network-LOCKED: a
/// non-global zoned task whose zone lacks POLICY_FLAG_ALLOW_NETWORK. Returns
/// None (allow) for unzoned, global, or network-allowed callers.
#[inline(always)]
fn network_locked_caller(ctx: &LsmContext) -> Option<u32> {
    let caller = lookup_caller_zone(ctx)?;
    if caller.flags & ZONE_FLAG_GLOBAL != 0 {
        return None;
    }
    if let Some(policy) = ZONE_POLICY.get(caller.zone_id) {
        if policy.flags & POLICY_FLAG_ALLOW_NETWORK != 0 {
            return None;
        }
    }
    Some(caller.zone_id)
}

/// Deny when `addr_ptr` is a non-loopback AF_INET/AF_INET6 endpoint; allow
/// loopback, NULL, and non-IP families. When `egress` is set, an IPv4
/// destination covered by the zone's CIDR allowlist is also allowed.
#[inline(always)]
fn gate_remote(addr_ptr: u64, caller_zone: u32, hook: u8, egress: bool) -> Result<i32, i64> {
    if addr_ptr == 0 {
        return Ok(0);
    }
    let family = unsafe { read_kernel_u16(addr_ptr, 0)? };
    if family != AF_INET && family != AF_INET6 {
        return Ok(0);
    }
    if unsafe { is_loopback(addr_ptr, family)? } {
        return Ok(0);
    }
    // Egress CIDR allowlist (IPv4 only): a locked zone may still reach a
    // destination an operator explicitly permitted.
    if egress && family == AF_INET {
        let addr = unsafe { read_kernel_u32(addr_ptr, 4)? };
        if egress_cidr_allows(caller_zone, addr) {
            return Ok(0);
        }
    }
    emit_deny_event(hook, caller_zone, ZONE_ID_HOST, family as u64);
    Ok(-1)
}

/// Loopback detection on the little-endian bpfel target.
/// IPv4: sockaddr_in.sin_addr at offset 4; 127.0.0.0/8 has high octet 127,
/// the low byte of the network-order word read on a LE host.
/// IPv6: sockaddr_in6.sin6_addr at offset 8; ::1 is fifteen zero bytes then
/// 0x01 (high u64 == 0, low u64 == 0x0100000000000000 on LE).
#[inline(always)]
unsafe fn is_loopback(addr_ptr: u64, family: u16) -> Result<bool, i64> {
    if family == AF_INET {
        let s_addr = read_kernel_u32(addr_ptr, 4)?;
        return Ok(s_addr & 0xff == 127);
    }
    let hi = read_kernel_u64(addr_ptr, 8)?;
    let lo = read_kernel_u64(addr_ptr, 16)?;
    Ok(hi == 0 && lo == 0x0100_0000_0000_0000)
}

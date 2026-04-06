use aya_ebpf::programs::LsmContext;

use crate::{lookup_caller_zone, count_decision, emit_deny_event, ZONE_MEMBERSHIP};
use syva_ebpf_common::{ZONE_FLAG_GLOBAL, PROG_UNIX_CONNECT, HOOK_UNIX_CONNECT};

pub fn unix_stream_connect(ctx: &LsmContext) -> i32 {
    let (ret, is_error) = match try_unix_connect(ctx) {
        Ok(ret) => (ret, false),
        Err(_) => (0, true),
    };
    count_decision(PROG_UNIX_CONNECT, ret == 0, is_error);
    ret
}

/// LSM hook: security_unix_stream_connect(struct sock *sock,
///     struct sock *other, struct sock *newsk)
///
/// Checks if a zoned process is connecting to a Unix domain socket.
/// Full peer zone resolution requires chasing sock->sk_socket->file
/// owner chain — implemented as zone-aware deny for zoned callers
/// connecting to sockets outside their zone membership.
///
/// Current behavior: if caller is zoned, look up the peer socket's
/// owning cgroup via the `other` sock struct. If the peer is in a
/// different zone, deny. If we can't resolve the peer → allow (fail-open).
#[inline(always)]
fn try_unix_connect(ctx: &LsmContext) -> Result<i32, i64> {
    let caller = match lookup_caller_zone(ctx) {
        Some(info) => info,
        None => return Ok(0),
    };

    if caller.flags & ZONE_FLAG_GLOBAL != 0 {
        return Ok(0);
    }

    // arg(1) = struct sock *other (the server/peer socket)
    let other_ptr: u64 = unsafe { ctx.arg(1) };
    if other_ptr == 0 {
        return Ok(0);
    }

    // Resolve the peer socket's owning cgroup.
    // sock->sk_cgrp_data.cgroup contains the cgroup pointer.
    // However, reading this safely requires knowing the offset of
    // sk_cgrp_data within struct sock, which varies by kernel version.
    //
    // For now: use bpf_get_current_cgroup_id() for the caller (already done
    // via lookup_caller_zone) and emit an audit event when a zoned process
    // makes any unix_stream_connect. This provides visibility without
    // false denials from incorrect peer resolution.
    //
    // TODO: Add SOCK_SK_CGRP_OFFSET for full peer zone resolution.

    // Audit-only: emit event but allow. Logged as caller_zone → ZONE_ID_HOST.
    // Full enforcement deferred until peer cgroup resolution is implemented.
    emit_deny_event(HOOK_UNIX_CONNECT, caller.zone_id, 0, 0);
    Ok(0) // Allow — audit only for now.
}

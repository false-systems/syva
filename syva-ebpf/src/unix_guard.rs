use aya_ebpf::programs::LsmContext;

use crate::{
    emit_deny_event, finish_decision, is_cross_zone_allowed, lookup_caller_zone,
    read_sock_cgroup_id, SELF_TEST_UNIX, ZONE_MEMBERSHIP,
};
use syva_ebpf_common::{
    SelfTestUnixResult, HOOK_UNIX_CONNECT, PROG_UNIX_CONNECT, ZONE_FLAG_GLOBAL, ZONE_ID_HOST,
};

pub fn unix_stream_connect(ctx: &LsmContext) -> i32 {
    finish_decision(PROG_UNIX_CONNECT, try_unix_connect(ctx))
}

/// LSM hook: security_unix_stream_connect(struct sock *sock,
///     struct sock *other, struct sock *newsk)
///
/// Resolves the server socket's (other) owning cgroup via
/// sock→sk_cgrp_data.cgroup→kn→id, looks up its zone in
/// ZONE_MEMBERSHIP, and applies cross-zone enforcement.
#[inline(always)]
fn try_unix_connect(ctx: &LsmContext) -> Result<i32, i64> {
    // arg(1) = struct sock *other (the server/listener socket)
    let other_ptr: u64 = unsafe { ctx.arg(1) };
    if other_ptr == 0 {
        return Ok(0);
    }

    // Resolve the server socket's cgroup_id via sk_cgrp_data.
    let peer_cgroup_id = unsafe { read_sock_cgroup_id(other_ptr)? };

    // One-shot self-test: write the first resolved peer cgroup_id so
    // userspace can verify the offset chain produces sane values.
    unsafe { maybe_write_self_test(peer_cgroup_id) };

    let caller = match lookup_caller_zone(ctx) {
        Some(info) => info,
        None => return Ok(0),
    };

    if caller.flags & ZONE_FLAG_GLOBAL != 0 {
        return Ok(0);
    }

    let peer = match unsafe { ZONE_MEMBERSHIP.get(&peer_cgroup_id) } {
        Some(info) => info,
        None => {
            // Peer is a host/unzoned process. Zoned caller must not
            // connect to unzoned Unix sockets.
            emit_deny_event(
                HOOK_UNIX_CONNECT,
                caller.zone_id,
                ZONE_ID_HOST,
                peer_cgroup_id,
            );
            return Ok(-1);
        }
    };

    if is_cross_zone_allowed(caller.zone_id, peer.zone_id) {
        return Ok(0);
    }

    emit_deny_event(
        HOOK_UNIX_CONNECT,
        caller.zone_id,
        peer.zone_id,
        peer_cgroup_id,
    );
    Ok(-1)
}

#[inline(always)]
unsafe fn maybe_write_self_test(peer_cgroup_id: u64) {
    if let Some(existing) = SELF_TEST_UNIX.get(0) {
        if existing.peer_cgroup_id != 0 {
            return;
        }
    }
    let result = SelfTestUnixResult { peer_cgroup_id };
    if let Some(slot) = SELF_TEST_UNIX.get_ptr_mut(0) {
        *slot = result;
    }
}

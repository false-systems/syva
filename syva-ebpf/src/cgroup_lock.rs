use aya_ebpf::programs::LsmContext;

use crate::{lookup_caller_zone, read_kernel_u64, count_decision, emit_deny_event, offsets, ZONE_MEMBERSHIP};
use syva_ebpf_common::{ZONE_FLAG_GLOBAL, PROG_CGROUP_ATTACH, HOOK_CGROUP_ATTACH};

pub fn cgroup_attach_task(ctx: &LsmContext) -> i32 {
    let (ret, is_error) = match try_cgroup_attach(ctx) {
        Ok(ret) => (ret, false),
        Err(_) => (0, true),
    };
    count_decision(PROG_CGROUP_ATTACH, ret == 0, is_error);
    ret
}

#[inline(always)]
fn try_cgroup_attach(ctx: &LsmContext) -> Result<i32, i64> {
    let caller = match lookup_caller_zone(ctx) {
        Some(info) => info,
        None => return Ok(0),
    };

    if caller.flags & ZONE_FLAG_GLOBAL != 0 {
        return Ok(0);
    }

    let dst_cgrp_ptr: u64 = unsafe { ctx.arg(0) };
    if dst_cgrp_ptr == 0 { return Ok(0); }

    let kn_ptr = unsafe { read_kernel_u64(dst_cgrp_ptr, offsets::cgroup_kn())? };
    if kn_ptr == 0 { return Ok(0); }
    let dst_cgroup_id = unsafe { read_kernel_u64(kn_ptr, offsets::kernfs_node_id())? };

    let dst_zone = unsafe { ZONE_MEMBERSHIP.get(&dst_cgroup_id) };

    match dst_zone {
        Some(dst_info) => {
            // Same-zone cgroup migration is permitted by design (L1).
            // Containers within the same zone share resource boundaries.
            if caller.zone_id == dst_info.zone_id {
                Ok(0)
            } else {
                emit_deny_event(HOOK_CGROUP_ATTACH, caller.zone_id, dst_info.zone_id, dst_cgroup_id);
                Ok(-1)
            }
        }
        None => {
            emit_deny_event(HOOK_CGROUP_ATTACH, caller.zone_id, 0, dst_cgroup_id);
            Ok(-1)
        }
    }
}

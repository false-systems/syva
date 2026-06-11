use aya_ebpf::programs::FEntryContext;

use crate::{read_cgrp_id, read_task_cgroup_id, record_escape, ZONE_MEMBERSHIP};
use syva_ebpf_common::ZONE_FLAG_GLOBAL;

/// Detection only: fentry on `cgroup_attach_task(struct cgroup *dst_cgrp,
///     struct task_struct *leader, bool threadgroup)`.
///
/// Runs at function entry, before the task migrates, so the leader's *source*
/// cgroup is still readable. fentry cannot deny the move — detection only.
pub fn detect_escape(ctx: &FEntryContext) {
    let _ = try_detect(ctx);
}

#[inline(always)]
fn try_detect(ctx: &FEntryContext) -> Result<(), i64> {
    let dst_cgrp: u64 = unsafe { ctx.arg(0) };
    let leader: u64 = unsafe { ctx.arg(1) };

    // Source cgroup of the migrating task — read before the migration happens.
    let src_cgroup_id = unsafe { read_task_cgroup_id(leader)? };
    let src_zone = match unsafe { ZONE_MEMBERSHIP.get(&src_cgroup_id) } {
        Some(info) => *info,
        // The task is not in any zone — there is no zone to escape from.
        None => return Ok(()),
    };
    if src_zone.flags & ZONE_FLAG_GLOBAL != 0 {
        return Ok(());
    }

    let dst_cgroup_id = unsafe { read_cgrp_id(dst_cgrp)? };
    if dst_cgroup_id == src_cgroup_id {
        return Ok(());
    }

    // Moving to another cgroup in the same zone is legitimate.
    if let Some(dst) = unsafe { ZONE_MEMBERSHIP.get(&dst_cgroup_id) } {
        if dst.zone_id == src_zone.zone_id {
            return Ok(());
        }
    }

    // A zoned task is leaving its zone for an unzoned or different-zone cgroup.
    record_escape(src_zone.zone_id, dst_cgroup_id);
    Ok(())
}

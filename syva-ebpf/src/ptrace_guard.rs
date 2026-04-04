use aya_ebpf::programs::LsmContext;

use crate::{lookup_caller_zone, check_cross_zone_task_access, count_decision, ZONE_POLICY};
use syva_ebpf_common::{ZONE_FLAG_GLOBAL, POLICY_FLAG_ALLOW_PTRACE, PROG_PTRACE_CHECK, HOOK_PTRACE_CHECK};

pub fn ptrace_access_check(ctx: &LsmContext) -> i32 {
    let (ret, is_error) = match try_ptrace_check(ctx) {
        Ok(ret) => (ret, false),
        Err(_) => (0, true),
    };
    count_decision(PROG_PTRACE_CHECK, ret == 0, is_error);
    ret
}

#[inline(always)]
fn try_ptrace_check(ctx: &LsmContext) -> Result<i32, i64> {
    let caller = match lookup_caller_zone(ctx) {
        Some(info) => info,
        None => return Ok(0),
    };

    if caller.flags & ZONE_FLAG_GLOBAL != 0 {
        return Ok(0);
    }

    if let Some(policy) = unsafe { ZONE_POLICY.get(&caller.zone_id) } {
        if policy.flags & POLICY_FLAG_ALLOW_PTRACE != 0 {
            return Ok(0);
        }
    }

    check_cross_zone_task_access(ctx, HOOK_PTRACE_CHECK)
}

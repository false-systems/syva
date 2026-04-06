use aya_ebpf::programs::LsmContext;

use crate::{lookup_caller_zone, lookup_task_zone, is_cross_zone_allowed,
            count_decision, emit_deny_event, ZONE_POLICY};
use syva_ebpf_common::{ZONE_FLAG_GLOBAL, ZONE_ID_HOST, POLICY_FLAG_ALLOW_PTRACE,
                        PROG_PTRACE_CHECK, HOOK_PTRACE_CHECK};

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

    // Read ptrace mode for granular policy and forensic logging.
    // arg(1) = unsigned int mode (PTRACE_MODE_READ=0x4, PTRACE_MODE_ATTACH=0x1)
    let mode: u64 = unsafe { ctx.arg(1) };

    // Resolve target zone FIRST — before any policy check.
    let target_ptr: u64 = unsafe { ctx.arg(0) };
    if target_ptr == 0 { return Ok(0); }

    let target = match unsafe { lookup_task_zone(target_ptr) } {
        Some(info) => info,
        None => {
            // Target is a host process — deny from any zoned caller.
            emit_deny_event(HOOK_PTRACE_CHECK, caller.zone_id, ZONE_ID_HOST, mode);
            return Ok(-1);
        }
    };

    // Same zone: allow only if POLICY_FLAG_ALLOW_PTRACE is set.
    if caller.zone_id == target.zone_id {
        if let Some(policy) = unsafe { ZONE_POLICY.get(caller.zone_id) } {
            if policy.flags & POLICY_FLAG_ALLOW_PTRACE != 0 {
                return Ok(0);
            }
        }
        // Same zone but ptrace not permitted by policy.
        emit_deny_event(HOOK_PTRACE_CHECK, caller.zone_id, target.zone_id, mode);
        return Ok(-1);
    }

    // Cross-zone: always deny regardless of mode or ZONE_ALLOWED_COMMS.
    // ZONE_ALLOWED_COMMS grants file/signal access, NOT ptrace attach.
    // Cross-zone ptrace is a privilege escalation vector.
    emit_deny_event(HOOK_PTRACE_CHECK, caller.zone_id, target.zone_id, mode);
    Ok(-1)
}

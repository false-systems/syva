use aya_ebpf::programs::LsmContext;

use crate::{lookup_caller_zone, is_cross_zone_allowed, read_file_ino, read_kernel_u64,
            count_decision, emit_deny_event, offsets, INODE_ZONE_MAP};
use syva_ebpf_common::{ZONE_FLAG_GLOBAL, PROG_BPRM_CHECK, HOOK_BPRM_CHECK};

pub fn bprm_check_security(ctx: &LsmContext) -> i32 {
    let (ret, is_error) = match try_bprm_check(ctx) {
        Ok(ret) => (ret, false),
        Err(_) => (0, true),
    };
    count_decision(PROG_BPRM_CHECK, ret == 0, is_error);
    ret
}

#[inline(always)]
fn try_bprm_check(ctx: &LsmContext) -> Result<i32, i64> {
    let caller = match lookup_caller_zone(ctx) {
        Some(info) => info,
        None => return Ok(0),
    };

    if caller.flags & ZONE_FLAG_GLOBAL != 0 {
        return Ok(0);
    }

    let bprm_ptr: u64 = unsafe { ctx.arg(0) };
    if bprm_ptr == 0 { return Ok(0); }

    let file_ptr = unsafe { read_kernel_u64(bprm_ptr, offsets::bprm_file())? };
    let ino = unsafe { read_file_ino(file_ptr)? };

    let file_zone_id = match unsafe { INODE_ZONE_MAP.get(&ino) } {
        Some(&zone_id) => zone_id,
        None => return Ok(0),
    };

    if caller.zone_id == file_zone_id {
        return Ok(0);
    }

    if is_cross_zone_allowed(caller.zone_id, file_zone_id) {
        return Ok(0);
    }

    emit_deny_event(HOOK_BPRM_CHECK, caller.zone_id, file_zone_id, ino);
    Ok(-1)
}

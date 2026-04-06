use aya_ebpf::programs::LsmContext;

use crate::{lookup_caller_zone, is_cross_zone_allowed, read_file_ino, maybe_run_self_test,
            count_decision, emit_deny_event, INODE_ZONE_MAP};
use syva_ebpf_common::{ZONE_FLAG_GLOBAL, PROG_FILE_OPEN, HOOK_FILE_OPEN};

pub fn file_open(ctx: &LsmContext) -> i32 {
    unsafe { maybe_run_self_test(ctx) };

    let (ret, is_error) = match try_file_open(ctx) {
        Ok(ret) => (ret, false),
        Err(_) => (0, true),
    };
    count_decision(PROG_FILE_OPEN, ret == 0, is_error);
    ret
}

#[inline(always)]
fn try_file_open(ctx: &LsmContext) -> Result<i32, i64> {
    let caller = match lookup_caller_zone(ctx) {
        Some(info) => info,
        None => return Ok(0),
    };

    if caller.flags & ZONE_FLAG_GLOBAL != 0 {
        return Ok(0);
    }

    let file_ptr: u64 = unsafe { ctx.arg(0) };
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

    emit_deny_event(HOOK_FILE_OPEN, caller.zone_id, file_zone_id, ino);
    Ok(-1)
}

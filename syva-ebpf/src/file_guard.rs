use aya_ebpf::programs::LsmContext;

use crate::{
    emit_deny_event, finish_decision, is_cross_zone_allowed, lookup_caller_zone,
    maybe_run_self_test, read_file_key, INODE_ZONE_MAP,
};
use syva_ebpf_common::{HOOK_FILE_OPEN, PROG_FILE_OPEN, ZONE_FLAG_GLOBAL};

pub fn file_open(ctx: &LsmContext) -> i32 {
    unsafe { maybe_run_self_test(ctx) };
    finish_decision(PROG_FILE_OPEN, try_file_open(ctx))
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
    let key = unsafe { read_file_key(file_ptr)? };

    let file_zone_id = match unsafe { INODE_ZONE_MAP.get(&key) } {
        Some(&zone_id) => zone_id,
        None => return Ok(0),
    };

    if caller.zone_id == file_zone_id {
        return Ok(0);
    }

    if is_cross_zone_allowed(caller.zone_id, file_zone_id) {
        return Ok(0);
    }

    emit_deny_event(HOOK_FILE_OPEN, caller.zone_id, file_zone_id, key.ino);
    Ok(-1)
}

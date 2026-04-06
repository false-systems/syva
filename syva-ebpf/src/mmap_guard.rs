use aya_ebpf::programs::LsmContext;

use crate::{lookup_caller_zone, is_cross_zone_allowed, read_file_ino,
            count_decision, emit_deny_event, INODE_ZONE_MAP};
use syva_ebpf_common::{ZONE_FLAG_GLOBAL, PROG_MMAP_FILE, HOOK_MMAP_FILE};

/// PROT_EXEC flag value from linux/mman.h.
const PROT_EXEC: u64 = 0x4;

pub fn mmap_file(ctx: &LsmContext) -> i32 {
    let (ret, is_error) = match try_mmap_file(ctx) {
        Ok(ret) => (ret, false),
        Err(_) => (0, true),
    };
    count_decision(PROG_MMAP_FILE, ret == 0, is_error);
    ret
}

/// LSM hook: security_mmap_file(struct file *file, unsigned long reqprot,
///     unsigned long prot, unsigned long flags)
///
/// Only enforces when PROT_EXEC is requested — read/write-only mappings
/// are not a cross-zone code execution vector.
#[inline(always)]
fn try_mmap_file(ctx: &LsmContext) -> Result<i32, i64> {
    // arg(0) = file *, arg(1) = reqprot, arg(2) = prot, arg(3) = flags
    let prot: u64 = unsafe { ctx.arg(2) };
    if prot & PROT_EXEC == 0 {
        return Ok(0); // Not an executable mapping — skip.
    }

    let caller = match lookup_caller_zone(ctx) {
        Some(info) => info,
        None => return Ok(0),
    };

    if caller.flags & ZONE_FLAG_GLOBAL != 0 {
        return Ok(0);
    }

    let file_ptr: u64 = unsafe { ctx.arg(0) };
    if file_ptr == 0 {
        return Ok(0); // Anonymous mapping — no file to check.
    }

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

    emit_deny_event(HOOK_MMAP_FILE, caller.zone_id, file_zone_id, ino);
    Ok(-1)
}

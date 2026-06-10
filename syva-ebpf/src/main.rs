#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{lsm, map},
    maps::{ring_buf::RingBuf, Array, HashMap, PerCpuArray},
    programs::LsmContext,
};
use syva_ebpf_common::{
    EnforcementCounters, EnforcementEvent, SelfTestInodeResult, SelfTestResult, SelfTestUnixResult,
    ZoneCommKey, ZoneInfoKernel, ZonePolicyKernel, DECISION_DENY, DECISION_WOULD_DENY,
    ENFORCEMENT_COUNTER_ENTRIES, MAX_CGROUPS, MAX_INODES, MAX_ZONES, MAX_ZONE_COMM_PAIRS,
    MODE_AUDIT,
};

mod exec_guard;
mod file_guard;
mod mmap_guard;
mod ptrace_guard;
mod signal_guard;
mod unix_guard;

#[map]
static ZONE_MEMBERSHIP: HashMap<u64, ZoneInfoKernel> = HashMap::with_max_entries(MAX_CGROUPS, 0);

#[map]
static ZONE_POLICY: Array<ZonePolicyKernel> = Array::with_max_entries(MAX_ZONES, 0);

#[map]
// Known limitation: this key is i_ino only, not (dev, ino), so distinct
// filesystems can collide. Userspace docs track the required map-key upgrade.
static INODE_ZONE_MAP: HashMap<u64, u32> = HashMap::with_max_entries(MAX_INODES, 1); // BPF_F_NO_PREALLOC

#[map]
static ZONE_ALLOWED_COMMS: HashMap<ZoneCommKey, u8> =
    HashMap::with_max_entries(MAX_ZONE_COMM_PAIRS, 0);

#[map]
static SELF_TEST: Array<SelfTestResult> = Array::with_max_entries(1, 0);

#[map]
static SELF_TEST_INODE: Array<SelfTestInodeResult> = Array::with_max_entries(1, 0);

#[map]
static SELF_TEST_INODE_TARGET: Array<u64> = Array::with_max_entries(1, 0);

#[map]
static SELF_TEST_UNIX: Array<SelfTestUnixResult> = Array::with_max_entries(1, 0);

#[map]
static ENFORCEMENT_COUNTERS: PerCpuArray<EnforcementCounters> =
    PerCpuArray::with_max_entries(ENFORCEMENT_COUNTER_ENTRIES, 0);

#[map]
// Global enforcement mode (index 0): MODE_ENFORCE denies return -1;
// MODE_AUDIT records the deny decision but lets the operation proceed.
// Userspace writes it once at startup before the hooks attach.
static ENFORCEMENT_MODE: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static ENFORCEMENT_EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 4096, 0); // 4MB

#[inline(always)]
fn lookup_caller_zone(_ctx: &LsmContext) -> Option<ZoneInfoKernel> {
    let cgroup_id = unsafe { aya_ebpf::helpers::bpf_get_current_cgroup_id() };
    unsafe { ZONE_MEMBERSHIP.get(&cgroup_id).copied() }
}

#[inline(always)]
unsafe fn read_kernel_u64(base: u64, offset: usize) -> Result<u64, i64> {
    let addr = (base + offset as u64) as *const u64;
    aya_ebpf::helpers::bpf_probe_read_kernel(addr).map_err(|e| e as i64)
}

#[no_mangle]
static TASK_CGROUPS_OFFSET: u64 = 2336;
#[no_mangle]
static CSS_SET_DFL_CGRP_OFFSET: u64 = 48;
#[no_mangle]
static CGROUP_KN_OFFSET: u64 = 64;
#[no_mangle]
static KERNFS_NODE_ID_OFFSET: u64 = 0;
#[no_mangle]
static FILE_F_INODE_OFFSET: u64 = 32;
#[no_mangle]
static INODE_I_INO_OFFSET: u64 = 64;
#[no_mangle]
static BPRM_FILE_OFFSET: u64 = 168;
#[no_mangle]
static SOCK_CGRP_DATA_CGROUP_OFFSET: u64 = 696;

mod offsets {
    #[inline(always)]
    pub fn task_cgroups() -> usize {
        unsafe { core::ptr::read_volatile(&super::TASK_CGROUPS_OFFSET) as usize }
    }
    #[inline(always)]
    pub fn css_set_dfl_cgrp() -> usize {
        unsafe { core::ptr::read_volatile(&super::CSS_SET_DFL_CGRP_OFFSET) as usize }
    }
    #[inline(always)]
    pub fn cgroup_kn() -> usize {
        unsafe { core::ptr::read_volatile(&super::CGROUP_KN_OFFSET) as usize }
    }
    #[inline(always)]
    pub fn kernfs_node_id() -> usize {
        unsafe { core::ptr::read_volatile(&super::KERNFS_NODE_ID_OFFSET) as usize }
    }
    #[inline(always)]
    pub fn file_f_inode() -> usize {
        unsafe { core::ptr::read_volatile(&super::FILE_F_INODE_OFFSET) as usize }
    }
    #[inline(always)]
    pub fn inode_i_ino() -> usize {
        unsafe { core::ptr::read_volatile(&super::INODE_I_INO_OFFSET) as usize }
    }
    #[inline(always)]
    pub fn bprm_file() -> usize {
        unsafe { core::ptr::read_volatile(&super::BPRM_FILE_OFFSET) as usize }
    }
    #[inline(always)]
    pub fn sock_cgrp_data_cgroup() -> usize {
        unsafe { core::ptr::read_volatile(&super::SOCK_CGRP_DATA_CGROUP_OFFSET) as usize }
    }
}

#[inline(always)]
unsafe fn read_task_cgroup_id(task_ptr: u64) -> Result<u64, i64> {
    if task_ptr == 0 {
        return Err(-1);
    }
    let cgroups_ptr = read_kernel_u64(task_ptr, offsets::task_cgroups())?;
    if cgroups_ptr == 0 {
        return Err(-1);
    }
    let dfl_cgrp_ptr = read_kernel_u64(cgroups_ptr, offsets::css_set_dfl_cgrp())?;
    if dfl_cgrp_ptr == 0 {
        return Err(-1);
    }
    let kn_ptr = read_kernel_u64(dfl_cgrp_ptr, offsets::cgroup_kn())?;
    if kn_ptr == 0 {
        return Err(-1);
    }
    read_kernel_u64(kn_ptr, offsets::kernfs_node_id())
}

#[inline(always)]
unsafe fn lookup_task_zone(task_ptr: u64) -> Option<ZoneInfoKernel> {
    let cgroup_id = read_task_cgroup_id(task_ptr).ok()?;
    ZONE_MEMBERSHIP.get(&cgroup_id).copied()
}

/// Resolve a sock pointer to its owning cgroup_id.
/// Chain: sock → sk_cgrp_data.cgroup → kn → id (reuses existing cgroup offsets).
#[inline(always)]
unsafe fn read_sock_cgroup_id(sock_ptr: u64) -> Result<u64, i64> {
    if sock_ptr == 0 {
        return Err(-1);
    }
    let cgrp_ptr = read_kernel_u64(sock_ptr, offsets::sock_cgrp_data_cgroup())?;
    if cgrp_ptr == 0 {
        return Err(-1);
    }
    let kn_ptr = read_kernel_u64(cgrp_ptr, offsets::cgroup_kn())?;
    if kn_ptr == 0 {
        return Err(-1);
    }
    read_kernel_u64(kn_ptr, offsets::kernfs_node_id())
}

#[inline(always)]
unsafe fn read_file_ino(file_ptr: u64) -> Result<u64, i64> {
    if file_ptr == 0 {
        return Err(-1);
    }
    let inode_ptr = read_kernel_u64(file_ptr, offsets::file_f_inode())?;
    if inode_ptr == 0 {
        return Err(-1);
    }
    read_kernel_u64(inode_ptr, offsets::inode_i_ino())
}

#[inline(always)]
fn is_cross_zone_allowed(src_zone: u32, dst_zone: u32) -> bool {
    if src_zone == dst_zone {
        return true;
    }
    let key = ZoneCommKey { src_zone, dst_zone };
    unsafe { ZONE_ALLOWED_COMMS.get(&key).is_some() }
}

/// True when userspace has switched the global mode to audit (observe-only).
/// Missing map entry means enforce — audit must always be an explicit choice.
#[inline(always)]
fn audit_mode_active() -> bool {
    matches!(ENFORCEMENT_MODE.get(0), Some(&MODE_AUDIT))
}

#[inline(always)]
fn emit_deny_event(hook: u8, caller_zone: u32, target_zone: u32, context: u64) {
    let pid = (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32;
    let ts = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    let decision = if audit_mode_active() {
        DECISION_WOULD_DENY
    } else {
        DECISION_DENY
    };

    let event = EnforcementEvent {
        timestamp_ns: ts,
        pid,
        hook,
        decision,
        _pad0: [0; 2],
        caller_zone,
        target_zone,
        context,
        _reserved: [0; 2],
    };

    if let Some(mut entry) = ENFORCEMENT_EVENTS.reserve::<EnforcementEvent>(0) {
        entry.write(event);
        entry.submit(0);
    } else {
        // Ring buffer full — increment lost counter for this hook.
        count_lost(hook);
    }
}

/// Increment the lost event counter for a hook when ring buffer reserve fails.
#[inline(always)]
fn count_lost(hook: u8) {
    if let Some(counters) = ENFORCEMENT_COUNTERS.get_ptr_mut(hook as u32) {
        let c = unsafe { &mut *counters };
        c.lost += 1;
    }
}

#[inline(always)]
fn check_cross_zone_task_access(ctx: &LsmContext, hook: u8) -> Result<i32, i64> {
    let caller = match lookup_caller_zone(ctx) {
        Some(info) => info,
        None => return Ok(0),
    };

    if caller.flags & syva_ebpf_common::ZONE_FLAG_GLOBAL != 0 {
        return Ok(0);
    }

    let target_ptr: u64 = unsafe { ctx.arg(0) };
    if target_ptr == 0 {
        return Ok(0);
    }

    let target = match unsafe { lookup_task_zone(target_ptr) } {
        Some(info) => info,
        None => {
            // Target is a host process (not in any zone).
            // A zoned caller must not signal or ptrace host processes.
            emit_deny_event(hook, caller.zone_id, syva_ebpf_common::ZONE_ID_HOST, 0);
            return Ok(-1);
        }
    };

    if is_cross_zone_allowed(caller.zone_id, target.zone_id) {
        return Ok(0);
    }

    emit_deny_event(hook, caller.zone_id, target.zone_id, 0);
    Ok(-1)
}

#[inline(always)]
unsafe fn maybe_run_self_test(ctx: &LsmContext) {
    let run_cgroup_self_test = match SELF_TEST.get(0) {
        Some(existing) => existing.helper_cgroup_id == 0,
        None => true,
    };
    if run_cgroup_self_test {
        // Cgroup offset self-test: compare BPF helper vs offset chain.
        let helper_id = aya_ebpf::helpers::bpf_get_current_cgroup_id();
        let task_ptr = aya_ebpf::helpers::bpf_get_current_task() as u64;
        let offset_id = read_task_cgroup_id(task_ptr).unwrap_or(0);

        let result = SelfTestResult {
            helper_cgroup_id: helper_id,
            offset_cgroup_id: offset_id,
        };

        if let Some(slot) = SELF_TEST.get_ptr_mut(0) {
            *slot = result;
        }
    }

    // Inode offset self-test: derive inode via file->f_inode->i_ino chain.
    // Userspace will compare this against stat() of the same file.
    let file_ptr: u64 = ctx.arg(0);
    if let Ok(ino) = read_file_ino(file_ptr) {
        let target_ino = SELF_TEST_INODE_TARGET.get(0).copied().unwrap_or(0);
        if target_ino == 0 || ino == target_ino {
            let inode_result = SelfTestInodeResult { offset_ino: ino };
            if let Some(slot) = SELF_TEST_INODE.get_ptr_mut(0) {
                *slot = inode_result;
            }
        }
    }
}

#[inline(always)]
fn count_decision(prog_idx: u32, allow: bool, is_error: bool) {
    if let Some(counters) = ENFORCEMENT_COUNTERS.get_ptr_mut(prog_idx) {
        let c = unsafe { &mut *counters };
        if is_error {
            c.error += 1;
        } else if allow {
            c.allow += 1;
        } else {
            c.deny += 1;
        }
    }
}

/// Shared hook epilogue: count the decision, then translate a deny verdict
/// through the global enforcement mode. The `deny` counter records the
/// DECISION (incremented in both modes); only the return value differs —
/// enforce mode blocks with -1 (EPERM), audit mode lets the operation
/// proceed after the would-deny event has been emitted.
#[inline(always)]
fn finish_decision(prog_idx: u32, verdict: Result<i32, i64>) -> i32 {
    let (ret, is_error) = match verdict {
        Ok(ret) => (ret, false),
        Err(_) => (0, true),
    };
    count_decision(prog_idx, ret == 0, is_error);
    if ret == 0 {
        0
    } else if audit_mode_active() {
        0
    } else {
        -1
    }
}

// --- LSM hook entry points ---

#[lsm(hook = "file_open")]
pub fn syva_file_open(ctx: LsmContext) -> i32 {
    file_guard::file_open(&ctx)
}

#[lsm(hook = "bprm_check_security")]
pub fn syva_bprm_check(ctx: LsmContext) -> i32 {
    exec_guard::bprm_check_security(&ctx)
}

#[lsm(hook = "ptrace_access_check")]
pub fn syva_ptrace_check(ctx: LsmContext) -> i32 {
    ptrace_guard::ptrace_access_check(&ctx)
}

#[lsm(hook = "task_kill")]
pub fn syva_task_kill(ctx: LsmContext) -> i32 {
    signal_guard::task_kill(&ctx)
}

#[lsm(hook = "mmap_file")]
pub fn syva_mmap_file(ctx: LsmContext) -> i32 {
    mmap_guard::mmap_file(&ctx)
}

#[lsm(hook = "unix_stream_connect")]
pub fn syva_unix_connect(ctx: LsmContext) -> i32 {
    unix_guard::unix_stream_connect(&ctx)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

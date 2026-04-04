use aya_ebpf::programs::LsmContext;

use crate::{check_cross_zone_task_access, count_decision};
use syva_ebpf_common::{PROG_TASK_KILL, HOOK_TASK_KILL};

pub fn task_kill(ctx: &LsmContext) -> i32 {
    let (ret, is_error) = match check_cross_zone_task_access(ctx, HOOK_TASK_KILL) {
        Ok(ret) => (ret, false),
        Err(_) => (0, true),
    };
    count_decision(PROG_TASK_KILL, ret == 0, is_error);
    ret
}

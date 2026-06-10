use aya_ebpf::programs::LsmContext;

use crate::{check_cross_zone_task_access, finish_decision};
use syva_ebpf_common::{HOOK_TASK_KILL, PROG_TASK_KILL};

pub fn task_kill(ctx: &LsmContext) -> i32 {
    finish_decision(PROG_TASK_KILL, check_cross_zone_task_access(ctx, HOOK_TASK_KILL))
}

#ifndef LANES
#define LANES 8
#endif
/* 16,384 64-byte records per lane. With four active producer CPUs, the
 * benchmark exposes the same 4 MiB of usable record storage as Aya's shared
 * ring buffer. The remaining CPU lanes stay reserved for the fixed topology.
 */
#ifndef CAPACITY
#define CAPACITY 524288
#endif
#define MOLD_LANES LANES
#define MOLD_CAPACITY CAPACITY
#define MOLD_WORDS 6
#include "mold.h"

__attribute__((section("maps"), used))
struct map_def target = {2, sizeof(u32), sizeof(u32), 1, 0};

static u64 (*const ktime_get_ns)(void) = (void *)5;
static u64 (*const get_current_pid_tgid)(void) = (void *)14;
static u64 (*const get_smp_processor_id)(void) = (void *)8;

__attribute__((section("tracepoint/syscalls/sys_enter_getpid"), used))
int controlled_marked(void *ctx) {
    u32 zero = 0;
    u32 *wanted = map_lookup_elem(&target, &zero);
    u64 pid_tgid = get_current_pid_tgid();
    if (!wanted || *wanted != (u32)(pid_tgid >> 32)) return 0;
    u32 cpu = (u32)get_smp_processor_id();
    u64 words[MOLD_WORDS] = {
        ktime_get_ns(), 0, (u32)pid_tgid, (u32)(pid_tgid >> 32), cpu, 0,
    };
    mold_publish(cpu, words);
    return 0;
}

__attribute__((section("license"), used))
char program_license[] = "GPL";

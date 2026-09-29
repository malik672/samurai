#ifndef LANES
#define LANES 8
#endif
#ifndef CAPACITY
#define CAPACITY 524288
#endif
#define MOLD_LANES LANES
#define MOLD_CAPACITY CAPACITY
#define MOLD_WORDS 19
#include "mold.h"

struct config { u32 pid, pointer_offset, length_offset, mode, enabled; };
__attribute__((section("maps"), used))
struct map_def config = {2, sizeof(u32), sizeof(struct config), 1, 0};

static u64 (*const ktime_get_ns)(void) = (void *)5;
static u64 (*const get_current_pid_tgid)(void) = (void *)14;
static u64 (*const get_smp_processor_id)(void) = (void *)8;
static long (*const probe_read_kernel)(void *, u32, const void *) = (void *)113;
static long (*const probe_read_user)(void *, u32, const void *) = (void *)112;
static long (*const probe_read_user_str)(void *, u32, const void *) = (void *)114;

static __attribute__((always_inline)) int emit(void *ctx, u32 expected_mode) {
    u32 zero = 0;
    struct config *cfg = map_lookup_elem(&config, &zero);
    u64 pid_tgid = get_current_pid_tgid();
    if (!cfg || !cfg->enabled || cfg->pid != (u32)(pid_tgid >> 32) ||
        cfg->mode != expected_mode)
        return 0;
    u64 pointer = 0, length = 128;
    if (probe_read_kernel(&pointer, 8, (char *)ctx + cfg->pointer_offset) < 0)
        return 0;
    if (expected_mode == 2 &&
        probe_read_kernel(&length, 8, (char *)ctx + cfg->length_offset) < 0)
        return 0;
    u64 words[MOLD_WORDS] = {ktime_get_ns(), length};
    long result = expected_mode == 1
        ? probe_read_user_str(&words[3], 128, (void *)pointer)
        : probe_read_user(&words[3], 128, (void *)pointer);
    words[2] = (u64)result;
    mold_publish((u32)get_smp_processor_id(), words);
    return 0;
}

__attribute__((section("tracepoint/syscalls/sys_enter_openat"), used))
int controlled_string(void *ctx) { return emit(ctx, 1); }

__attribute__((section("tracepoint/syscalls/sys_enter_write"), used))
int controlled_bytes(void *ctx) { return emit(ctx, 2); }

__attribute__((section("license"), used))
char program_license[] = "GPL";

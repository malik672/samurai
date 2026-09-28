#define MOLD_WORDS 15
#define MOLD_CAPACITY 65536
#include "mold.h"

static u64 (*const ktime_get_ns)(void) = (void *)5;
static u64 (*const get_current_pid_tgid)(void) = (void *)14;
static u64 (*const get_smp_processor_id)(void) = (void *)8;
static long (*const probe_read_user_str)(void *, u32, const void *) = (void *)114;

struct sys_enter {
    u64 common;
    long syscall_number;
    unsigned long args[6];
};

__attribute__((section("tracepoint/syscalls/sys_enter_openat"), used))
int record_openat(struct sys_enter *ctx) {
    u32 cpu = (u32)get_smp_processor_id();
    u64 words[MOLD_WORDS] = {};
    words[0] = ktime_get_ns();
    words[1] = (u32)(get_current_pid_tgid() >> 32);
    words[2] = cpu;
    words[3] = (u64)(long)ctx->args[0];
    words[4] = (u32)ctx->args[2];
    words[5] = (u32)ctx->args[3];
    long path_len = probe_read_user_str(&words[7], 64, (const void *)ctx->args[1]);
    words[6] = path_len > 0 ? (u32)(path_len - 1) : 0;
    mold_publish(cpu, words);
    return 0;
}

__attribute__((section("license"), used))
char program_license[] = "GPL";

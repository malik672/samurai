#define MOLD_WORDS 6
#include "mold.h"

static u64 (*const ktime_get_ns)(void) = (void *)5;
static u64 (*const get_current_pid_tgid)(void) = (void *)14;
static u64 (*const get_smp_processor_id)(void) = (void *)8;

struct sys_enter {
    u64 common;
    long syscall_number;
    unsigned long args[6];
};

__attribute__((section("tracepoint/syscalls/sys_enter_openat"), used))
int record_openat(struct sys_enter *ctx) {
    u32 cpu = (u32)get_smp_processor_id();
    u64 words[MOLD_WORDS] = {
        ktime_get_ns(),
        (u32)(get_current_pid_tgid() >> 32),
        cpu,
        (u64)(long)ctx->args[0],
        (u32)ctx->args[2],
        (u32)ctx->args[3],
    };
    mold_publish(cpu, words);
    return 0;
}

__attribute__((section("license"), used))
char program_license[] = "GPL";

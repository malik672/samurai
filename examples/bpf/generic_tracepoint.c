#define MOLD_WORDS 34
#ifndef MOLD_CAPACITY
#define MOLD_CAPACITY 65536
#endif
#include "mold.h"

#define CAPTURE_OPERATIONS 32
#define CAPTURE_SIGNED 1U

static u64 (*const ktime_get_ns)(void) = (void *)5;
static u64 (*const get_smp_processor_id)(void) = (void *)8;
static long (*const probe_read_kernel)(void *, u32, const void *) = (void *)113;

struct capture_operation {
    u32 source_offset;
    unsigned short size;
    unsigned short destination_word;
    u32 flags;
    u32 reserved;
};

__attribute__((section("maps"), used))
struct map_def capture_config = {2, sizeof(u32), sizeof(u64), 1, 0};

__attribute__((section("maps"), used))
struct map_def capture_operations = {
    2, sizeof(u32), sizeof(struct capture_operation), CAPTURE_OPERATIONS, 0
};

static __attribute__((always_inline)) u64
sign_extend(u64 value, unsigned short size) {
    if (size == 1) return (u64)(long long)(signed char)value;
    if (size == 2) return (u64)(long long)(signed short)value;
    if (size == 4) return (u64)(long long)(signed int)value;
    return value;
}

__attribute__((section("tracepoint/samurai/generic"), used))
int record_generic_tracepoint(void *ctx) {
    u32 zero = 0;
    u64 *operation_count = map_lookup_elem(&capture_config, &zero);
    if (!operation_count || *operation_count > CAPTURE_OPERATIONS) return 0;

    u32 cpu = (u32)get_smp_processor_id();
    u64 words[MOLD_WORDS] = {};
    words[0] = ktime_get_ns();
    words[1] = cpu;

    for (u32 index = 0; index < CAPTURE_OPERATIONS; index++) {
        if (index >= *operation_count) break;
        struct capture_operation *operation =
            map_lookup_elem(&capture_operations, &index);
        if (!operation || operation->destination_word >= MOLD_WORDS) return 0;
        u64 value = 0;
        unsigned short size = operation->size;
        if (size != 1 && size != 2 && size != 4 && size != 8) return 0;
        if (probe_read_kernel(&value, size,
                              (const char *)ctx + operation->source_offset) < 0)
            return 0;
        if (operation->flags & CAPTURE_SIGNED)
            value = sign_extend(value, size);
        words[operation->destination_word] = value;
    }

    mold_publish(cpu, words);
    return 0;
}

__attribute__((section("license"), used))
char program_license[] = "GPL";

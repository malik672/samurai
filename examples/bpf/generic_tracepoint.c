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

struct capture_scratch {
    u64 words[MOLD_WORDS];
};

__attribute__((section("maps"), used))
struct map_def capture_config = {2, sizeof(u32), sizeof(u64), 1, 0};

__attribute__((section("maps"), used))
struct map_def capture_operations = {
    2, sizeof(u32), sizeof(struct capture_operation), CAPTURE_OPERATIONS, 0
};

__attribute__((section("maps"), used))
struct map_def capture_scratch = {
    6, sizeof(u32), sizeof(struct capture_scratch), 1, 0
};

static __attribute__((always_inline)) u64
sign_extend(u64 value, unsigned short size) {
    if (size == 1) return (u64)(long long)(signed char)value;
    if (size == 2) return (u64)(long long)(signed short)value;
    if (size == 4) return (u64)(long long)(signed int)value;
    return value;
}

static __attribute__((always_inline)) int
capture_one(void *ctx, u32 index, u64 *captured) {
    struct capture_operation *operation =
        map_lookup_elem(&capture_operations, &index);
    if (!operation) return 0;
    u64 value = 0;
    unsigned short size = operation->size;
    /* A fixed byte field may end with a partial word of any size from 1..=8. */
    if (size == 0 || size > sizeof(value)) return 0;
    if (probe_read_kernel(&value, size,
                          (const char *)ctx + operation->source_offset) < 0)
        return 0;
    if (operation->flags & CAPTURE_SIGNED)
        value = sign_extend(value, size);
    *captured = value;
    return 1;
}

#define DEFINE_STORE(word)                                                     \
    static __attribute__((noinline)) void store_word_##word(                   \
        struct capture_scratch *scratch, u64 value) {                          \
        scratch->words[word] = value;                                           \
    }
DEFINE_STORE(2)
DEFINE_STORE(3)
DEFINE_STORE(4)
DEFINE_STORE(5)
DEFINE_STORE(6)
DEFINE_STORE(7)
DEFINE_STORE(8)
DEFINE_STORE(9)
DEFINE_STORE(10)
DEFINE_STORE(11)
DEFINE_STORE(12)
DEFINE_STORE(13)
DEFINE_STORE(14)
DEFINE_STORE(15)
DEFINE_STORE(16)
DEFINE_STORE(17)
DEFINE_STORE(18)
DEFINE_STORE(19)
DEFINE_STORE(20)
DEFINE_STORE(21)
DEFINE_STORE(22)
DEFINE_STORE(23)
DEFINE_STORE(24)
DEFINE_STORE(25)
DEFINE_STORE(26)
DEFINE_STORE(27)
DEFINE_STORE(28)
DEFINE_STORE(29)
DEFINE_STORE(30)
DEFINE_STORE(31)
DEFINE_STORE(32)
DEFINE_STORE(33)
#undef DEFINE_STORE

__attribute__((section("tracepoint/samurai/generic"), used))
int record_generic_tracepoint(void *ctx) {
    u32 zero = 0;
    u64 *configured_count = map_lookup_elem(&capture_config, &zero);
    if (!configured_count || *configured_count > CAPTURE_OPERATIONS) return 0;
    u64 operation_count = *configured_count;
    struct capture_scratch *scratch = map_lookup_elem(&capture_scratch, &zero);
    if (!scratch) return 0;

    u32 cpu = (u32)get_smp_processor_id();
    scratch->words[0] = ktime_get_ns();
    scratch->words[1] = cpu;

#define CAPTURE_INDEX(index, word)                                             \
    if (operation_count > (index)) {                                           \
        u64 captured;                                                          \
        if (!capture_one(ctx, (index), &captured)) return 0;                   \
        store_word_##word(scratch, captured);                                  \
    }
    CAPTURE_INDEX(0, 2);
    CAPTURE_INDEX(1, 3);
    CAPTURE_INDEX(2, 4);
    CAPTURE_INDEX(3, 5);
    CAPTURE_INDEX(4, 6);
    CAPTURE_INDEX(5, 7);
    CAPTURE_INDEX(6, 8);
    CAPTURE_INDEX(7, 9);
    CAPTURE_INDEX(8, 10);
    CAPTURE_INDEX(9, 11);
    CAPTURE_INDEX(10, 12);
    CAPTURE_INDEX(11, 13);
    CAPTURE_INDEX(12, 14);
    CAPTURE_INDEX(13, 15);
    CAPTURE_INDEX(14, 16);
    CAPTURE_INDEX(15, 17);
    CAPTURE_INDEX(16, 18);
    CAPTURE_INDEX(17, 19);
    CAPTURE_INDEX(18, 20);
    CAPTURE_INDEX(19, 21);
    CAPTURE_INDEX(20, 22);
    CAPTURE_INDEX(21, 23);
    CAPTURE_INDEX(22, 24);
    CAPTURE_INDEX(23, 25);
    CAPTURE_INDEX(24, 26);
    CAPTURE_INDEX(25, 27);
    CAPTURE_INDEX(26, 28);
    CAPTURE_INDEX(27, 29);
    CAPTURE_INDEX(28, 30);
    CAPTURE_INDEX(29, 31);
    CAPTURE_INDEX(30, 32);
    CAPTURE_INDEX(31, 33);
#undef CAPTURE_INDEX

    mold_publish(cpu, scratch->words);
    return 0;
}

__attribute__((section("license"), used))
char program_license[] = "GPL";

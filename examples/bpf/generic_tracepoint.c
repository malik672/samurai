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

static __attribute__((noinline)) int
store_word(struct capture_scratch *scratch, unsigned short destination, u64 value) {
    switch (destination) {
    case 2: scratch->words[2] = value; break;
    case 3: scratch->words[3] = value; break;
    case 4: scratch->words[4] = value; break;
    case 5: scratch->words[5] = value; break;
    case 6: scratch->words[6] = value; break;
    case 7: scratch->words[7] = value; break;
    case 8: scratch->words[8] = value; break;
    case 9: scratch->words[9] = value; break;
    case 10: scratch->words[10] = value; break;
    case 11: scratch->words[11] = value; break;
    case 12: scratch->words[12] = value; break;
    case 13: scratch->words[13] = value; break;
    case 14: scratch->words[14] = value; break;
    case 15: scratch->words[15] = value; break;
    case 16: scratch->words[16] = value; break;
    case 17: scratch->words[17] = value; break;
    case 18: scratch->words[18] = value; break;
    case 19: scratch->words[19] = value; break;
    case 20: scratch->words[20] = value; break;
    case 21: scratch->words[21] = value; break;
    case 22: scratch->words[22] = value; break;
    case 23: scratch->words[23] = value; break;
    case 24: scratch->words[24] = value; break;
    case 25: scratch->words[25] = value; break;
    case 26: scratch->words[26] = value; break;
    case 27: scratch->words[27] = value; break;
    case 28: scratch->words[28] = value; break;
    case 29: scratch->words[29] = value; break;
    case 30: scratch->words[30] = value; break;
    case 31: scratch->words[31] = value; break;
    case 32: scratch->words[32] = value; break;
    case 33: scratch->words[33] = value; break;
    default: return 0;
    }
    return 1;
}

static __attribute__((always_inline)) int
capture_one(void *ctx, struct capture_scratch *scratch, u32 index) {
    struct capture_operation *operation =
        map_lookup_elem(&capture_operations, &index);
    if (!operation) return 0;
    u64 value = 0;
    unsigned short size = operation->size;
    if (size != 1 && size != 2 && size != 4 && size != 8) return 0;
    if (probe_read_kernel(&value, size,
                          (const char *)ctx + operation->source_offset) < 0)
        return 0;
    if (operation->flags & CAPTURE_SIGNED)
        value = sign_extend(value, size);
    return store_word(scratch, operation->destination_word, value);
}

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

#define CAPTURE_INDEX(index)                                                   \
    if (operation_count > (index) && !capture_one(ctx, scratch, (index)))     \
        return 0
    CAPTURE_INDEX(0);
    CAPTURE_INDEX(1);
    CAPTURE_INDEX(2);
    CAPTURE_INDEX(3);
    CAPTURE_INDEX(4);
    CAPTURE_INDEX(5);
    CAPTURE_INDEX(6);
    CAPTURE_INDEX(7);
    CAPTURE_INDEX(8);
    CAPTURE_INDEX(9);
    CAPTURE_INDEX(10);
    CAPTURE_INDEX(11);
    CAPTURE_INDEX(12);
    CAPTURE_INDEX(13);
    CAPTURE_INDEX(14);
    CAPTURE_INDEX(15);
    CAPTURE_INDEX(16);
    CAPTURE_INDEX(17);
    CAPTURE_INDEX(18);
    CAPTURE_INDEX(19);
    CAPTURE_INDEX(20);
    CAPTURE_INDEX(21);
    CAPTURE_INDEX(22);
    CAPTURE_INDEX(23);
    CAPTURE_INDEX(24);
    CAPTURE_INDEX(25);
    CAPTURE_INDEX(26);
    CAPTURE_INDEX(27);
    CAPTURE_INDEX(28);
    CAPTURE_INDEX(29);
    CAPTURE_INDEX(30);
    CAPTURE_INDEX(31);
#undef CAPTURE_INDEX

    mold_publish(cpu, scratch->words);
    return 0;
}

__attribute__((section("license"), used))
char program_license[] = "GPL";

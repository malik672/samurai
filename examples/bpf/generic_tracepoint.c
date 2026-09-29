#define MOLD_WORDS 34
#ifndef MOLD_CAPACITY
#define MOLD_CAPACITY 65536
#endif
#include "mold.h"

#define CAPTURE_OPERATIONS 32
#define CAPTURE_SIGNED 1U
#define CAPTURE_DATA_LOC 2U
#define CAPTURE_RELATIVE 4U
#define CAPTURE_DYNAMIC_METADATA 8U
#define CAPTURE_USER_STRING 16U

static u64 (*const ktime_get_ns)(void) = (void *)5;
static u64 (*const get_smp_processor_id)(void) = (void *)8;
static u64 (*const get_current_pid_tgid)(void) = (void *)14;
static long (*const probe_read_kernel)(void *, u32, const void *) = (void *)113;
static long (*const probe_read_user_str)(void *, u32, const void *) = (void *)114;

struct capture_operation {
    u32 source_offset;
    unsigned short size;
    unsigned short destination_word;
    u32 flags;
    u32 data_offset;
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

#define DEFINE_READ(size)                                                       \
    static __attribute__((noinline)) int read_##size(                           \
        void *ctx, u32 source_offset, u64 *value) {                             \
        return probe_read_kernel(value, size,                                   \
                                 (const char *)ctx + source_offset);             \
    }
DEFINE_READ(1)
DEFINE_READ(2)
DEFINE_READ(3)
DEFINE_READ(4)
DEFINE_READ(5)
DEFINE_READ(6)
DEFINE_READ(7)
DEFINE_READ(8)
#undef DEFINE_READ

static __attribute__((always_inline)) int
read_fixed(void *ctx, u32 source_offset, unsigned short size, u64 *value) {
    switch (size) {
    case 1: return read_1(ctx, source_offset, value);
    case 2: return read_2(ctx, source_offset, value);
    case 3: return read_3(ctx, source_offset, value);
    case 4: return read_4(ctx, source_offset, value);
    case 5: return read_5(ctx, source_offset, value);
    case 6: return read_6(ctx, source_offset, value);
    case 7: return read_7(ctx, source_offset, value);
    case 8: return read_8(ctx, source_offset, value);
    default: return -1;
    }
}

#define DEFINE_USER_STRING(word)                                                \
    static __attribute__((noinline)) long read_user_string_##word(              \
        void *ctx, u32 source_offset, u32 pointer_size,                         \
        struct capture_scratch *scratch) {                                      \
        u64 pointer = 0;                                                        \
        if (read_fixed(ctx, source_offset, (unsigned short)pointer_size,         \
                       &pointer) < 0)                                           \
            return -1;                                                         \
        __builtin_memset(&scratch->words[(word) + 1], 0, 128);                  \
        return probe_read_user_str(&scratch->words[(word) + 1], 128,            \
                                   (const void *)pointer);                      \
    }
DEFINE_USER_STRING(2)
DEFINE_USER_STRING(3)
DEFINE_USER_STRING(4)
DEFINE_USER_STRING(5)
DEFINE_USER_STRING(6)
DEFINE_USER_STRING(7)
DEFINE_USER_STRING(8)
DEFINE_USER_STRING(9)
DEFINE_USER_STRING(10)
DEFINE_USER_STRING(11)
DEFINE_USER_STRING(12)
DEFINE_USER_STRING(13)
DEFINE_USER_STRING(14)
DEFINE_USER_STRING(15)
DEFINE_USER_STRING(16)
DEFINE_USER_STRING(17)
#undef DEFINE_USER_STRING

static __attribute__((always_inline)) long
read_user_string(void *ctx, struct capture_operation *operation,
                 struct capture_scratch *scratch) {
    switch (operation->destination_word) {
    case 2: return read_user_string_2(ctx, operation->source_offset, operation->data_offset, scratch);
    case 3: return read_user_string_3(ctx, operation->source_offset, operation->data_offset, scratch);
    case 4: return read_user_string_4(ctx, operation->source_offset, operation->data_offset, scratch);
    case 5: return read_user_string_5(ctx, operation->source_offset, operation->data_offset, scratch);
    case 6: return read_user_string_6(ctx, operation->source_offset, operation->data_offset, scratch);
    case 7: return read_user_string_7(ctx, operation->source_offset, operation->data_offset, scratch);
    case 8: return read_user_string_8(ctx, operation->source_offset, operation->data_offset, scratch);
    case 9: return read_user_string_9(ctx, operation->source_offset, operation->data_offset, scratch);
    case 10: return read_user_string_10(ctx, operation->source_offset, operation->data_offset, scratch);
    case 11: return read_user_string_11(ctx, operation->source_offset, operation->data_offset, scratch);
    case 12: return read_user_string_12(ctx, operation->source_offset, operation->data_offset, scratch);
    case 13: return read_user_string_13(ctx, operation->source_offset, operation->data_offset, scratch);
    case 14: return read_user_string_14(ctx, operation->source_offset, operation->data_offset, scratch);
    case 15: return read_user_string_15(ctx, operation->source_offset, operation->data_offset, scratch);
    case 16: return read_user_string_16(ctx, operation->source_offset, operation->data_offset, scratch);
    case 17: return read_user_string_17(ctx, operation->source_offset, operation->data_offset, scratch);
    default: return -1;
    }
}

static __attribute__((always_inline)) int
capture_one(void *ctx, u32 index, struct capture_scratch *scratch, u64 *captured) {
    struct capture_operation *operation =
        map_lookup_elem(&capture_operations, &index);
    if (!operation) return 0;
    u64 value = 0;
    unsigned short size = operation->size;
    if (operation->flags & CAPTURE_USER_STRING) {
        long result = read_user_string(ctx, operation, scratch);
        u32 length = result > 0 ? (u32)(result - 1) : 0;
        u32 error = result < 0 ? (u32)result : 0;
        *captured = ((u64)error << 32) | length;
        return 1;
    }
    if (operation->flags & CAPTURE_DATA_LOC) {
        u64 locator_word = 0;
        if (read_4(ctx, operation->source_offset, &locator_word) < 0)
            return 0;
        u32 locator = (u32)locator_word;
        u32 data_start = locator & 0xffffU;
        u32 data_length = locator >> 16;
        if (operation->flags & CAPTURE_RELATIVE)
            data_start += operation->source_offset;
        if (operation->flags & CAPTURE_DYNAMIC_METADATA) {
            u32 captured_length = data_length;
            if (captured_length > size) captured_length = size;
            *captured = ((u64)data_length << 32) | captured_length;
            return 1;
        }
        if (operation->data_offset >= data_length) {
            *captured = 0;
            return 1;
        }
        u32 remaining = data_length - operation->data_offset;
        if (remaining < size) size = (unsigned short)remaining;
        if (read_fixed(ctx, data_start + operation->data_offset, size, &value) < 0)
            return 0;
        *captured = value;
        return 1;
    }
    if (read_fixed(ctx, operation->source_offset, size, &value) < 0)
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
    u32 pid = (u32)(get_current_pid_tgid() >> 32);
    scratch->words[0] = ktime_get_ns();
    scratch->words[1] = ((u64)pid << 32) | cpu;

#define CAPTURE_INDEX(index, word)                                             \
    if (operation_count > (index)) {                                           \
        u64 captured;                                                          \
        if (!capture_one(ctx, (index), scratch, &captured)) return 0;          \
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

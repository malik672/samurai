#define MOLD_WORDS 34
#ifndef MOLD_CAPACITY
#define MOLD_CAPACITY 65536
#endif
#include "mold.h"

#define CAPTURE_EVENTS 8
#define CAPTURE_OPERATIONS 30
#define CAPTURE_OPERATION_SLOTS (CAPTURE_EVENTS * CAPTURE_OPERATIONS)
#define CAPTURE_SIGNED 1U
#define CAPTURE_DATA_LOC 2U
#define CAPTURE_RELATIVE 4U
#define CAPTURE_DYNAMIC_METADATA 8U
#define CAPTURE_USER_STRING 16U
#define CAPTURE_POINTER_BYTES 32U
#define CAPTURE_KERNEL_MEMORY 64U

static u64 (*const ktime_get_ns)(void) = (void *)5;
static u64 (*const get_smp_processor_id)(void) = (void *)8;
static u64 (*const get_current_pid_tgid)(void) = (void *)14;
static long (*const get_current_comm)(void *, u32) = (void *)16;
static long (*const map_update_elem)(void *, const void *, const void *, u64) = (void *)2;
static long (*const map_delete_elem)(void *, const void *) = (void *)3;
static long (*const probe_read_kernel)(void *, u32, const void *) = (void *)113;
static long (*const probe_read_user)(void *, u32, const void *) = (void *)112;
static long (*const probe_read_user_str)(void *, u32, const void *) = (void *)114;
static long (*const probe_read_kernel_str)(void *, u32, const void *) = (void *)115;

struct capture_operation {
    u32 source_offset;
    unsigned short size;
    unsigned short destination_word;
    u32 flags;
    u32 data_offset;
    u32 auxiliary_offset;
    unsigned short pointer_size;
    unsigned short auxiliary_size;
};

struct capture_scratch {
    u64 words[MOLD_WORDS];
};

struct pid_filter_configuration {
    u32 enabled;
    u32 fork_parent_pid_offset;
    u32 fork_child_pid_offset;
    u32 fork_child_comm_offset;
};

struct process_metadata_value {
    u32 parent_pid;
    u32 reserved;
    char comm[16];
};

/* Values are compact lane indexes plus one; zero means the CPU is disabled. */
__attribute__((section("maps"), used))
struct map_def cpu_to_lane = {2, sizeof(u32), sizeof(u32), 1, 0};

__attribute__((section("maps"), used))
struct map_def capture_config = {2, sizeof(u32), sizeof(u64), CAPTURE_EVENTS, 0};

__attribute__((section("maps"), used))
struct map_def capture_operations = {
    2, sizeof(u32), sizeof(struct capture_operation), CAPTURE_OPERATION_SLOTS, 0
};

__attribute__((section("maps"), used))
struct map_def capture_scratch = {
    6, sizeof(u32), sizeof(struct capture_scratch), 1, 0
};

#ifndef TRACKED_PID_CAPACITY
#define TRACKED_PID_CAPACITY 65536
#endif
__attribute__((section("maps"), used))
struct map_def tracked_pids = {1, sizeof(u32), sizeof(unsigned char), TRACKED_PID_CAPACITY, 0};

__attribute__((section("maps"), used))
struct map_def process_metadata = {
    1, sizeof(u32), sizeof(struct process_metadata_value), TRACKED_PID_CAPACITY, 0
};

__attribute__((section("maps"), used))
struct map_def pid_filter_config = {
    2, sizeof(u32), sizeof(struct pid_filter_configuration), 1, 0
};

/* PID insertion failures, child insertions, removals, and metadata failures. */
__attribute__((section("maps"), used))
struct map_def pid_filter_stats = {2, sizeof(u32), sizeof(u64), 4, 0};

static __attribute__((always_inline)) void increment_pid_stat(u32 index) {
    u64 *value = map_lookup_elem(&pid_filter_stats, &index);
    if (value) __sync_fetch_and_add(value, 1);
}

static __attribute__((always_inline)) int pid_is_tracked(u32 pid) {
    return map_lookup_elem(&tracked_pids, &pid) != 0;
}

__attribute__((section("tracepoint/samurai/track_fork"), used))
int track_process_fork(void *ctx) {
    u32 zero = 0;
    struct pid_filter_configuration *config = map_lookup_elem(&pid_filter_config, &zero);
    if (!config || !config->enabled) return 0;
    if (config->fork_parent_pid_offset > 4096U ||
        config->fork_child_pid_offset > 4096U ||
        config->fork_child_comm_offset > 4096U)
        return 0;
    u32 parent_pid = 0;
    u32 child_pid = 0;
    if (probe_read_kernel(&parent_pid, sizeof(parent_pid),
                          (const char *)ctx + config->fork_parent_pid_offset) < 0 ||
        probe_read_kernel(&child_pid, sizeof(child_pid),
                          (const char *)ctx + config->fork_child_pid_offset) < 0)
        return 0;
    if (!pid_is_tracked(parent_pid)) return 0;
    unsigned char one = 1;
    if (map_update_elem(&tracked_pids, &child_pid, &one, 0) < 0) {
        increment_pid_stat(0);
    } else {
        increment_pid_stat(1);
    }
    struct process_metadata_value metadata = {};
    metadata.parent_pid = (u32)(get_current_pid_tgid() >> 32);
    if (probe_read_kernel(metadata.comm, sizeof(metadata.comm),
                          (const char *)ctx + config->fork_child_comm_offset) < 0 ||
        map_update_elem(&process_metadata, &child_pid, &metadata, 0) < 0)
        increment_pid_stat(3);
    return 0;
}

__attribute__((section("tracepoint/samurai/track_exec"), used))
int track_process_exec(void *ctx) {
    (void)ctx;
    u64 identity = get_current_pid_tgid();
    u32 pid = (u32)(identity >> 32);
    if (!pid_is_tracked(pid)) return 0;
    struct process_metadata_value *metadata =
        map_lookup_elem(&process_metadata, &pid);
    if (!metadata) {
        increment_pid_stat(3);
        return 0;
    }
    if (get_current_comm(metadata->comm, sizeof(metadata->comm)) < 0)
        increment_pid_stat(3);
    return 0;
}

__attribute__((section("tracepoint/samurai/track_exit"), used))
int track_process_exit(void *ctx) {
    (void)ctx;
    u64 identity = get_current_pid_tgid();
    u32 tid = (u32)identity;
    /* Fork tracking includes task IDs; remove exactly the task that exited. */
    if (pid_is_tracked(tid) && map_delete_elem(&tracked_pids, &tid) == 0)
        increment_pid_stat(2);
    return 0;
}

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
        u32 kernel_memory, struct capture_scratch *scratch) {                   \
        u64 pointer = 0;                                                        \
        if (read_fixed(ctx, source_offset, (unsigned short)pointer_size,         \
                       &pointer) < 0)                                           \
            return -1;                                                         \
        __builtin_memset(&scratch->words[(word) + 1], 0, 128);                  \
        if (kernel_memory)                                                      \
            return probe_read_kernel_str(&scratch->words[(word) + 1], 128,      \
                                         (const void *)pointer);                \
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
    u32 kernel_memory = operation->flags & CAPTURE_KERNEL_MEMORY;
    switch (operation->destination_word) {
    case 2: return read_user_string_2(ctx, operation->source_offset, operation->pointer_size, kernel_memory, scratch);
    case 3: return read_user_string_3(ctx, operation->source_offset, operation->pointer_size, kernel_memory, scratch);
    case 4: return read_user_string_4(ctx, operation->source_offset, operation->pointer_size, kernel_memory, scratch);
    case 5: return read_user_string_5(ctx, operation->source_offset, operation->pointer_size, kernel_memory, scratch);
    case 6: return read_user_string_6(ctx, operation->source_offset, operation->pointer_size, kernel_memory, scratch);
    case 7: return read_user_string_7(ctx, operation->source_offset, operation->pointer_size, kernel_memory, scratch);
    case 8: return read_user_string_8(ctx, operation->source_offset, operation->pointer_size, kernel_memory, scratch);
    case 9: return read_user_string_9(ctx, operation->source_offset, operation->pointer_size, kernel_memory, scratch);
    case 10: return read_user_string_10(ctx, operation->source_offset, operation->pointer_size, kernel_memory, scratch);
    case 11: return read_user_string_11(ctx, operation->source_offset, operation->pointer_size, kernel_memory, scratch);
    case 12: return read_user_string_12(ctx, operation->source_offset, operation->pointer_size, kernel_memory, scratch);
    case 13: return read_user_string_13(ctx, operation->source_offset, operation->pointer_size, kernel_memory, scratch);
    case 14: return read_user_string_14(ctx, operation->source_offset, operation->pointer_size, kernel_memory, scratch);
    case 15: return read_user_string_15(ctx, operation->source_offset, operation->pointer_size, kernel_memory, scratch);
    case 16: return read_user_string_16(ctx, operation->source_offset, operation->pointer_size, kernel_memory, scratch);
    case 17: return read_user_string_17(ctx, operation->source_offset, operation->pointer_size, kernel_memory, scratch);
    default: return -1;
    }
}

#define DEFINE_MEMORY_READ(size)                                                \
    static __attribute__((noinline)) int read_memory_##size(                    \
        u64 address, u32 kernel_memory, u64 *value) {                           \
        if (kernel_memory)                                                      \
            return probe_read_kernel(value, size, (const void *)address);       \
        return probe_read_user(value, size, (const void *)address);             \
    }
DEFINE_MEMORY_READ(1)
DEFINE_MEMORY_READ(2)
DEFINE_MEMORY_READ(3)
DEFINE_MEMORY_READ(4)
DEFINE_MEMORY_READ(5)
DEFINE_MEMORY_READ(6)
DEFINE_MEMORY_READ(7)
DEFINE_MEMORY_READ(8)
#undef DEFINE_MEMORY_READ

static __attribute__((always_inline)) int
read_memory(u64 address, u32 kernel_memory, unsigned short size, u64 *value) {
    switch (size) {
    case 1: return read_memory_1(address, kernel_memory, value);
    case 2: return read_memory_2(address, kernel_memory, value);
    case 3: return read_memory_3(address, kernel_memory, value);
    case 4: return read_memory_4(address, kernel_memory, value);
    case 5: return read_memory_5(address, kernel_memory, value);
    case 6: return read_memory_6(address, kernel_memory, value);
    case 7: return read_memory_7(address, kernel_memory, value);
    case 8: return read_memory_8(address, kernel_memory, value);
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
    if (operation->flags & CAPTURE_POINTER_BYTES) {
        u64 pointer = 0;
        u64 length_word = 0;
        if (read_fixed(ctx, operation->source_offset, operation->pointer_size,
                       &pointer) < 0 ||
            read_fixed(ctx, operation->auxiliary_offset,
                       operation->auxiliary_size, &length_word) < 0)
            return 0;
        u32 original_length = length_word > 0xffffffffULL
                                  ? 0xffffffffU
                                  : (u32)length_word;
        if (operation->flags & CAPTURE_DYNAMIC_METADATA) {
            u32 captured_length = original_length;
            if (captured_length > size) captured_length = size;
            *captured = ((u64)original_length << 32) | captured_length;
            return 1;
        }
        if (operation->data_offset >= original_length) {
            *captured = 0;
            return 1;
        }
        u32 remaining = original_length - operation->data_offset;
        if (remaining < size) size = (unsigned short)remaining;
        if (read_memory(pointer + operation->data_offset,
                        operation->flags & CAPTURE_KERNEL_MEMORY, size,
                        &value) < 0)
            return 0;
        *captured = value;
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

static __attribute__((noinline)) int
store_captured(u32 index, struct capture_scratch *scratch, u64 value) {
    struct capture_operation *operation =
        map_lookup_elem(&capture_operations, &index);
    if (!operation) return 0;
    switch (operation->destination_word) {
    case 2: store_word_2(scratch, value); return 1;
    case 3: store_word_3(scratch, value); return 1;
    case 4: store_word_4(scratch, value); return 1;
    case 5: store_word_5(scratch, value); return 1;
    case 6: store_word_6(scratch, value); return 1;
    case 7: store_word_7(scratch, value); return 1;
    case 8: store_word_8(scratch, value); return 1;
    case 9: store_word_9(scratch, value); return 1;
    case 10: store_word_10(scratch, value); return 1;
    case 11: store_word_11(scratch, value); return 1;
    case 12: store_word_12(scratch, value); return 1;
    case 13: store_word_13(scratch, value); return 1;
    case 14: store_word_14(scratch, value); return 1;
    case 15: store_word_15(scratch, value); return 1;
    case 16: store_word_16(scratch, value); return 1;
    case 17: store_word_17(scratch, value); return 1;
    case 18: store_word_18(scratch, value); return 1;
    case 19: store_word_19(scratch, value); return 1;
    case 20: store_word_20(scratch, value); return 1;
    case 21: store_word_21(scratch, value); return 1;
    case 22: store_word_22(scratch, value); return 1;
    case 23: store_word_23(scratch, value); return 1;
    case 24: store_word_24(scratch, value); return 1;
    case 25: store_word_25(scratch, value); return 1;
    case 26: store_word_26(scratch, value); return 1;
    case 27: store_word_27(scratch, value); return 1;
    case 28: store_word_28(scratch, value); return 1;
    case 29: store_word_29(scratch, value); return 1;
    case 30: store_word_30(scratch, value); return 1;
    case 31: store_word_31(scratch, value); return 1;
    case 32: store_word_32(scratch, value); return 1;
    case 33: store_word_33(scratch, value); return 1;
    default: return 0;
    }
}

static __attribute__((always_inline)) int
record_generic_tracepoint(void *ctx, u32 event_id) {
    u32 zero = 0;
    struct pid_filter_configuration *pid_config =
        map_lookup_elem(&pid_filter_config, &zero);
    u64 identity = get_current_pid_tgid();
    u32 pid = (u32)(identity >> 32);
    if (!pid_config || (pid_config->enabled && !pid_is_tracked(pid))) return 0;
    u64 *configured_count = map_lookup_elem(&capture_config, &event_id);
    if (!configured_count || *configured_count > CAPTURE_OPERATIONS) return 0;
    u64 operation_count = *configured_count;
    struct capture_scratch *scratch = map_lookup_elem(&capture_scratch, &zero);
    if (!scratch) return 0;

    u32 cpu = (u32)get_smp_processor_id();
    u32 *encoded_lane = map_lookup_elem(&cpu_to_lane, &cpu);
    if (!encoded_lane || *encoded_lane == 0) return 0;
    u32 lane = *encoded_lane - 1;
    scratch->words[0] = ktime_get_ns();
    scratch->words[1] = ((u64)pid << 32) | cpu;
    scratch->words[MOLD_WORDS - 2] = (u32)identity;
    scratch->words[MOLD_WORDS - 1] = event_id;
    u32 operation_base = event_id * CAPTURE_OPERATIONS;

#define CAPTURE_INDEX(index)                                                   \
    if (operation_count > (index)) {                                           \
        u64 captured;                                                          \
        if (!capture_one(ctx, operation_base + (index), scratch, &captured)) return 0; \
        if (!store_captured(operation_base + (index), scratch, captured)) return 0; \
    }
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
#undef CAPTURE_INDEX

    mold_publish(lane, scratch->words);
    return 0;
}

#define DEFINE_CAPTURE_PROGRAM(index)                                          \
    __attribute__((section("tracepoint/samurai/generic_" #index), used))       \
    int record_generic_tracepoint_##index(void *ctx) {                         \
        return record_generic_tracepoint(ctx, index);                          \
    }
DEFINE_CAPTURE_PROGRAM(0)
DEFINE_CAPTURE_PROGRAM(1)
DEFINE_CAPTURE_PROGRAM(2)
DEFINE_CAPTURE_PROGRAM(3)
DEFINE_CAPTURE_PROGRAM(4)
DEFINE_CAPTURE_PROGRAM(5)
DEFINE_CAPTURE_PROGRAM(6)
DEFINE_CAPTURE_PROGRAM(7)
#undef DEFINE_CAPTURE_PROGRAM

__attribute__((section("license"), used))
char program_license[] = "GPL";

typedef unsigned int u32;
typedef unsigned long long u64;

struct map_def { u32 type, key_size, value_size, max_entries, map_flags; };

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
#define WRITING (1ULL << 63)
#define BPF_F_MMAPABLE (1U << 10)

struct slot { u64 mark, kind, words[6]; };
struct frontier {
    u64 producer_mark;
    u64 producer_padding[7];
    u64 consumer_mark;
    u64 consumer_padding[7];
};

__attribute__((section("maps"), used))
struct map_def slots = {2, sizeof(u32), sizeof(struct slot), LANES * CAPACITY, BPF_F_MMAPABLE};
__attribute__((section("maps"), used))
struct map_def frontiers = {2, sizeof(u32), sizeof(struct frontier), LANES, BPF_F_MMAPABLE};
__attribute__((section("maps"), used))
struct map_def cursors = {6, sizeof(u32), sizeof(u64), 1, 0};
__attribute__((section("maps"), used))
struct map_def target = {2, sizeof(u32), sizeof(u32), 1, 0};

static void *(*const map_lookup_elem)(void *, const void *) = (void *)1;
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
    if (cpu >= LANES) return 0;
    u64 *cursor = map_lookup_elem(&cursors, &zero);
    if (!cursor) return 0;
    u64 mark = *cursor + 1;
    *cursor = mark;
    u32 key = cpu * CAPACITY + ((u32)(mark - 1) & (CAPACITY - 1));
    struct slot *slot = map_lookup_elem(&slots, &key);
    struct frontier *frontier = map_lookup_elem(&frontiers, &cpu);
    if (!slot || !frontier) return 0;

    __sync_lock_test_and_set(&slot->mark, WRITING | mark);
    slot->words[0] = ktime_get_ns();
    slot->words[1] = 0;
    slot->words[2] = (u32)pid_tgid;
    slot->words[3] = (u32)(pid_tgid >> 32);
    slot->words[4] = cpu;
    slot->words[5] = 0;
    slot->kind = 0;
    __sync_lock_test_and_set(&slot->mark, mark);
    __sync_lock_test_and_set(&frontier->producer_mark, mark);
    return 0;
}

__attribute__((section("license"), used))
char program_license[] = "GPL";

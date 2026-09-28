// Kernel scheduler aggregation: no ring buffer and no userspace consumer.
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

struct map_def {
    u32 type;
    u32 key_size;
    u32 value_size;
    u32 max_entries;
    u32 map_flags;
};

struct task_stats {
    u64 runtime_ns;
    u64 measured_timeslices;
    u64 max_timeslice_ns;
    u64 switches_in;
    u64 switches_out;
    u64 voluntary_switches;
    u64 involuntary_switches;
};

// BPF_MAP_TYPE_LRU_PERCPU_HASH. Each CPU mutates only its local value.
__attribute__((section("maps"), used))
struct map_def tasks = {10, sizeof(u32), sizeof(struct task_stats), 16384, 0};
__attribute__((section("maps"), used))
struct map_def last_switch = {6, sizeof(u32), sizeof(u64), 1, 0};
__attribute__((section("maps"), used))
struct map_def records = {6, sizeof(u32), sizeof(u64), 1, 0};

static u64 (*const ktime_get_ns)(void) = (void *)5;
static void *(*const map_lookup_elem)(void *, const void *) = (void *)1;
static long (*const map_update_elem)(void *, const void *, const void *, u64) = (void *)2;

struct trace_entry {
    u16 type;
    u8 flags;
    u8 preempt_count;
    int pid;
};

struct sched_switch_context {
    struct trace_entry common;
    char previous_comm[16];
    int previous_pid;
    int previous_priority;
    long previous_state;
    char next_comm[16];
    int next_pid;
    int next_priority;
};

static __attribute__((always_inline)) struct task_stats *get_task(u32 pid) {
    struct task_stats *stats = map_lookup_elem(&tasks, &pid);
    if (stats)
        return stats;
    struct task_stats zero = {};
    map_update_elem(&tasks, &pid, &zero, 0);
    return map_lookup_elem(&tasks, &pid);
}

__attribute__((section("tracepoint/sched/sched_switch"), used))
int aggregate_switch(struct sched_switch_context *ctx) {
    u32 key = 0;
    u64 now = ktime_get_ns();
    u64 runtime = 0;
    u64 *last = map_lookup_elem(&last_switch, &key);
    if (last) {
        if (*last)
            runtime = now - *last;
        *last = now;
    }

    u64 *record_count = map_lookup_elem(&records, &key);
    if (record_count)
        (*record_count)++;

    struct task_stats *previous = get_task((u32)ctx->previous_pid);
    if (previous) {
        previous->switches_out++;
        if (ctx->previous_state == 0)
            previous->involuntary_switches++;
        else
            previous->voluntary_switches++;
        if (runtime) {
            previous->runtime_ns += runtime;
            previous->measured_timeslices++;
            if (runtime > previous->max_timeslice_ns)
                previous->max_timeslice_ns = runtime;
        }
    }

    struct task_stats *next = get_task((u32)ctx->next_pid);
    if (next)
        next->switches_in++;
    return 0;
}

__attribute__((section("license"), used))
char program_license[] = "GPL";

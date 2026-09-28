// Compile without -g: this loader currently supports legacy maps, not BTF/CO-RE.
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

struct context_switch {
    u64 timestamp_ns;
    u64 runtime_ns;
    u32 previous_pid;
    u32 next_pid;
    u32 cpu;
    u32 reserved;
    long previous_state;
};

// BPF_MAP_TYPE_RINGBUF: one MiB shared ring, power-of-two sized.
__attribute__((section("maps"), used))
struct map_def events = {27, 0, 0, 1 << 20, 0};

// Record queue overflow without making the event format carry transport state.
__attribute__((section("maps"), used))
struct map_def dropped = {6, sizeof(u32), sizeof(u64), 1, 0};

// Each CPU is the sole writer of its previous switch timestamp.
__attribute__((section("maps"), used))
struct map_def last_switch = {6, sizeof(u32), sizeof(u64), 1, 0};

// Userspace reports consumer TIDs before attachment.
__attribute__((section("maps"), used))
struct map_def consumer_tids = {2, sizeof(u32), sizeof(u32) * 4, 1, 0};

static u64 (*const ktime_get_ns)(void) = (void *)5;
static u64 (*const get_smp_processor_id)(void) = (void *)8;
static void *(*const map_lookup_elem)(void *, const void *) = (void *)1;
static void *(*const ringbuf_reserve)(void *, u64, u64) = (void *)131;
static void (*const ringbuf_submit)(void *, u64) = (void *)132;

struct trace_entry {
    u16 type;
    u8 flags;
    u8 preempt_count;
    int pid;
};

// Layout exported by tracefs for sched/sched_switch on this native target.
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

static __attribute__((noinline)) int is_consumer_switch(struct sched_switch_context *ctx) {
    u32 key = 0;
    u32 *worker_tids = map_lookup_elem(&consumer_tids, &key);
    if (!worker_tids)
        return 0;
    return (worker_tids[0] &&
            (ctx->previous_pid == worker_tids[0] || ctx->next_pid == worker_tids[0])) ||
           (worker_tids[1] &&
            (ctx->previous_pid == worker_tids[1] || ctx->next_pid == worker_tids[1])) ||
           (worker_tids[2] &&
            (ctx->previous_pid == worker_tids[2] || ctx->next_pid == worker_tids[2])) ||
           (worker_tids[3] &&
            (ctx->previous_pid == worker_tids[3] || ctx->next_pid == worker_tids[3]));
}

__attribute__((section("tracepoint/sched/sched_switch"), used))
int record_switch(struct sched_switch_context *ctx) {
    if (is_consumer_switch(ctx))
        return 0;
    u64 now = ktime_get_ns();
    u32 key = 0;
    u64 runtime_ns = 0;
    u64 *previous_switch = map_lookup_elem(&last_switch, &key);
    if (previous_switch) {
        if (*previous_switch)
            runtime_ns = now - *previous_switch;
        *previous_switch = now;
    }

    struct context_switch *event = ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        u64 *count = map_lookup_elem(&dropped, &key);
        if (count)
            (*count)++;
        return 0;
    }
    event->timestamp_ns = now;
    event->runtime_ns = runtime_ns;
    event->previous_pid = ctx->previous_pid;
    event->next_pid = ctx->next_pid;
    event->cpu = get_smp_processor_id();
    event->reserved = 0;
    event->previous_state = ctx->previous_state;
    ringbuf_submit(event, 0);
    return 0;
}

__attribute__((section("license"), used))
char program_license[] = "GPL";

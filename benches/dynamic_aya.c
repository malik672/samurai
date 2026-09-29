typedef unsigned int u32;
typedef unsigned long long u64;
struct map_def { u32 type, key_size, value_size, max_entries, map_flags; };
struct config { u32 pid, pointer_offset, length_offset, mode; };
struct event { u64 timestamp_ns; long result; unsigned char payload[128]; };

__attribute__((section("maps"), used))
struct map_def DYNAMIC = {27, 0, 0, 4 * 1024 * 1024, 0};
__attribute__((section("maps"), used))
struct map_def DYNAMIC_DROPPED = {6, sizeof(u32), sizeof(u64), 1, 0};
__attribute__((section("maps"), used))
struct map_def DYNAMIC_CONFIG = {2, sizeof(u32), sizeof(struct config), 1, 0};
__attribute__((section("maps"), used))
struct map_def DYNAMIC_CPU = {2, sizeof(u32), sizeof(u32), 1, 0};

static void *(*const map_lookup_elem)(void *, const void *) = (void *)1;
static u64 (*const ktime_get_ns)(void) = (void *)5;
static u64 (*const get_current_pid_tgid)(void) = (void *)14;
static u32 (*const get_smp_processor_id)(void) = (void *)8;
static long (*const probe_read_kernel)(void *, u32, const void *) = (void *)113;
static long (*const probe_read_user)(void *, u32, const void *) = (void *)112;
static long (*const probe_read_user_str)(void *, u32, const void *) = (void *)114;
static void *(*const ringbuf_reserve)(void *, u64, u64) = (void *)131;
static void (*const ringbuf_submit)(void *, u64) = (void *)132;

static __attribute__((always_inline)) void increment_drop(void) {
    u32 zero = 0; u64 *value = map_lookup_elem(&DYNAMIC_DROPPED, &zero);
    if (value) (*value)++;
}

static __attribute__((always_inline)) int emit(void *ctx, u32 mode) {
    u32 zero = 0;
    struct config *cfg = map_lookup_elem(&DYNAMIC_CONFIG, &zero);
    u32 *cpu = map_lookup_elem(&DYNAMIC_CPU, &zero);
    if (!cfg || !cpu || *cpu != get_smp_processor_id() ||
        cfg->pid != (u32)(get_current_pid_tgid() >> 32) || cfg->mode != mode)
        return 0;
    u64 pointer = 0;
    if (probe_read_kernel(&pointer, 8, (char *)ctx + cfg->pointer_offset) < 0)
        return 0;
    struct event *event = ringbuf_reserve(&DYNAMIC, sizeof(*event), 0);
    if (!event) { increment_drop(); return 0; }
    event->timestamp_ns = ktime_get_ns();
    __builtin_memset(event->payload, 0, sizeof(event->payload));
    event->result = mode == 1
        ? probe_read_user_str(event->payload, sizeof(event->payload), (void *)pointer)
        : probe_read_user(event->payload, sizeof(event->payload), (void *)pointer);
    ringbuf_submit(event, 0);
    return 0;
}

__attribute__((section("tracepoint/syscalls/sys_enter_openat"), used))
int controlled_string(void *ctx) { return emit(ctx, 1); }
__attribute__((section("tracepoint/syscalls/sys_enter_write"), used))
int controlled_bytes(void *ctx) { return emit(ctx, 2); }
char _license[] __attribute__((section("license"), used)) = "GPL";

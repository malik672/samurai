// Compile without -g: this first loader supports legacy maps, not BTF/CO-RE.
typedef unsigned int u32;
typedef unsigned long long u64;

struct map_def {
    u32 type;
    u32 key_size;
    u32 value_size;
    u32 max_entries;
    u32 map_flags;
};

__attribute__((section("maps"), used))
struct map_def switches = {6, sizeof(u32), sizeof(u64), 1, 0};

static void *(*const map_lookup_elem)(void *, const void *) = (void *)1;

static __attribute__((noinline)) int increment(void) {
    u32 key = 0;
    u64 *count = map_lookup_elem(&switches, &key);
    if (count)
        (*count)++;
    return 0;
}

__attribute__((section("tracepoint/sched/sched_switch"), used))
int count_switches(void *ctx) {
    return increment();
}

__attribute__((section("license"), used))
char program_license[] = "GPL";

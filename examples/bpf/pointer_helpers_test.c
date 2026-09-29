/*
 * Live helper cases adapted from Aya's bpf_probe_read integration tests.
 * Source revision 8bcb4e390fde09ffd8d7e8c060e473c03d9b6601, MIT;
 * see LICENSES/aya-MIT.txt.
 */
typedef unsigned int u32;
typedef unsigned long long u64;

struct map_def { u32 type, key_size, value_size, max_entries, map_flags; };

#define BUFFER_LEN 128

struct test_config {
    u32 pid;
    u32 pathname_offset;
};

struct test_result {
    long user_bytes_error;
    long kernel_string_result;
    long kernel_bytes_error;
    unsigned char user_bytes[BUFFER_LEN];
    unsigned char kernel_string[BUFFER_LEN];
    unsigned char kernel_bytes[BUFFER_LEN];
};

__attribute__((section("maps"), used))
struct map_def test_config = {2, sizeof(u32), sizeof(struct test_config), 1, 0};
__attribute__((section("maps"), used))
struct map_def kernel_buffer = {2, sizeof(u32), BUFFER_LEN, 1, 0};
__attribute__((section("maps"), used))
struct map_def test_result = {2, sizeof(u32), sizeof(struct test_result), 1, 0};

static void *(*const map_lookup_elem)(void *, const void *) = (void *)1;
static u64 (*const get_current_pid_tgid)(void) = (void *)14;
static long (*const probe_read_user)(void *, u32, const void *) = (void *)112;
static long (*const probe_read_kernel)(void *, u32, const void *) = (void *)113;
static long (*const probe_read_kernel_str)(void *, u32, const void *) = (void *)115;

__attribute__((section("tracepoint/syscalls/sys_enter_openat"), used))
int test_pointer_helpers(void *ctx) {
    u32 zero = 0;
    struct test_config *config = map_lookup_elem(&test_config, &zero);
    if (!config || (u32)(get_current_pid_tgid() >> 32) != config->pid)
        return 0;
    struct test_result *result = map_lookup_elem(&test_result, &zero);
    unsigned char *kernel = map_lookup_elem(&kernel_buffer, &zero);
    if (!result || !kernel)
        return 0;

    u64 pathname = 0;
    if (probe_read_kernel(&pathname, sizeof(pathname),
                          (const char *)ctx + config->pathname_offset) < 0)
        return 0;

    __builtin_memset(result, 0, sizeof(*result));
    result->user_bytes_error =
        probe_read_user(result->user_bytes, BUFFER_LEN, (const void *)pathname);
    result->kernel_string_result =
        probe_read_kernel_str(result->kernel_string, BUFFER_LEN, kernel);
    result->kernel_bytes_error =
        probe_read_kernel(result->kernel_bytes, BUFFER_LEN, kernel);
    return 0;
}

char _license[] __attribute__((section("license"), used)) = "GPL";

__attribute__((section("tracepoint/sched/sched_switch"), used))
int bench_tracepoint(void *ctx) {
    return 0;
}

__attribute__((section("license"), used))
char bench_license[] = "GPL";

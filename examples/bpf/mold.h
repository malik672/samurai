#ifndef SAMURAI_MOLD_H
#define SAMURAI_MOLD_H

typedef unsigned int u32;
typedef unsigned long long u64;

struct map_def { u32 type, key_size, value_size, max_entries, map_flags; };

#ifndef MOLD_LANES
#define MOLD_LANES 8
#endif
#ifndef MOLD_CAPACITY
#define MOLD_CAPACITY 524288
#endif
#ifndef MOLD_WORDS
#error "define MOLD_WORDS before including mold.h"
#endif

#define MOLD_WRITING (1ULL << 63)
#define BPF_F_MMAPABLE (1U << 10)

struct mold_slot { u64 mark, kind, words[MOLD_WORDS]; };
struct mold_frontier {
    u64 producer_mark;
    u64 producer_padding[7];
    u64 consumer_mark;
    u64 consumer_padding[7];
};

__attribute__((section("maps"), used))
struct map_def slots = {
    2, sizeof(u32), sizeof(struct mold_slot),
    MOLD_LANES * MOLD_CAPACITY, BPF_F_MMAPABLE
};
__attribute__((section("maps"), used))
struct map_def frontiers = {
    2, sizeof(u32), sizeof(struct mold_frontier), MOLD_LANES, BPF_F_MMAPABLE
};
/* A one-entry per-CPU array gives every CPU its own cursor without atomics. */
__attribute__((section("maps"), used))
struct map_def cursors = {6, sizeof(u32), sizeof(u64), 1, 0};

static void *(*const map_lookup_elem)(void *, const void *) = (void *)1;

static __attribute__((always_inline)) int
mold_publish(u32 cpu, const u64 words[MOLD_WORDS]) {
    u32 zero = 0;
    if (cpu >= MOLD_LANES) return 0;
    u64 *cursor = map_lookup_elem(&cursors, &zero);
    if (!cursor) return 0;
    u64 mark = *cursor + 1;
    *cursor = mark;
    u32 key = cpu * MOLD_CAPACITY + ((u32)(mark - 1) & (MOLD_CAPACITY - 1));
    struct mold_slot *slot = map_lookup_elem(&slots, &key);
    struct mold_frontier *frontier = map_lookup_elem(&frontiers, &cpu);
    if (!slot || !frontier) return 0;

    __sync_lock_test_and_set(&slot->mark, MOLD_WRITING | mark);
#pragma unroll
    for (u32 index = 0; index < MOLD_WORDS; index++)
        slot->words[index] = words[index];
    slot->kind = 0;
    __sync_lock_test_and_set(&slot->mark, mark);
    __sync_lock_test_and_set(&frontier->producer_mark, mark);
    return 1;
}

#endif

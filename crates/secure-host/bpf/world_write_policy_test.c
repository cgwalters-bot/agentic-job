// SPDX-License-Identifier: (MIT OR Apache-2.0)
#include <assert.h>
#include <string.h>
// Exercise the actual entry-point activation guards without kernel helpers.
// Production compilation retains CO-RE; native mocks use ordinary addresses.
#define CORE
#define __builtin_preserve_access_index(address) (address)
#include "world_write.bpf.c"

static struct root_config test_config;
static struct runner_config test_runner;
static unsigned int reads;

static void *lookup_config(void *map, const void *key)
{
    assert(*(const u32 *)key == 0);
    return map == (void *)&runner_reads ? (void *)&test_runner : (void *)&test_config;
}

static long failed_read(void *destination, u32 size, const void *source)
{
    (void)destination;
    (void)size;
    (void)source;
    reads++;
    return -1;
}

static struct task_struct *no_task(void) { return 0; }

static void activation_guards(void)
{
    map_lookup = lookup_config;
    probe_read = failed_read;
    current_task = no_task;
    u64 permission[] = {0, 2, 0};
    u64 open[] = {0, 0};
    u64 setattr[] = {0, 0, 0, 0};
    u64 ptrace[] = {0, WW_PTRACE_READ, 0};
    assert(world_write_permission(permission) == 0);
    assert(world_write_open(open) == 0);
    assert(world_write_file_permission(permission) == 0);
    assert(world_write_setattr(setattr) == 0);
    assert(runner_read_check(ptrace) == 0);
    assert(reads == 0);

    // Each map enables only its own program.
    test_config.enabled = 1;
    assert(runner_read_check(ptrace) == 0);
    assert(reads == 0);
    test_config.enabled = 0;
    test_runner.enabled = 1;
    assert(world_write_permission(permission) == 0);
    assert(reads == 0);
    // An attach is Yama's to decide; a read whose task can't be read is refused.
    ptrace[1] = WW_PTRACE_ATTACH | WW_PTRACE_READ;
    assert(runner_read_check(ptrace) == 0);
    assert(reads == 0);
    ptrace[1] = WW_PTRACE_READ | WW_PTRACE_FSCREDS;
    assert(runner_read_check(ptrace) == -WW_EACCES);
    assert(reads == 1);
    reads = 0;

    test_config.enabled = 1;
    permission[2] = open[1] = setattr[3] = ptrace[2] = (u64)-1;
    assert(world_write_permission(permission) == -1);
    assert(world_write_open(open) == -1);
    assert(world_write_file_permission(permission) == -1);
    assert(world_write_setattr(setattr) == -1);
    assert(runner_read_check(ptrace) == -1);
    assert(reads == 0);
    test_config.enabled = test_runner.enabled = 0;
}

static long copying_read(void *destination, u32 size, const void *source)
{
    memcpy(destination, source, size);
    return 0;
}

static struct task_struct *caller;
static struct task_struct *current_caller(void) { return caller; }
static u64 caller_pid_tgid(void) { return (u64)(u32)caller->tgid << 32; }

// init (1) <- worker (10) <- step (20) <- child (30) <- grandchild (40),
// and an orphan (50) of an earlier step, reparented to init.
static void runner_reads_rule(void)
{
    map_lookup = lookup_config;
    probe_read = copying_read;
    current_task = current_caller;
    current_pid_tgid = caller_pid_tgid;
    struct cred root = {{0}, {0}}, runner = {{1001}, {1001}}, other = {{1002}, {1002}};
    struct task_struct init = {1, 0, &root, &root};
    init.real_parent = &init;
    struct task_struct worker = {10, &init, &runner, &runner};
    struct task_struct step = {20, &worker, &runner, &runner};
    struct task_struct child = {30, &step, &runner, &runner};
    struct task_struct grandchild = {40, &child, &runner, &runner};
    struct task_struct orphan = {50, &init, &runner, &runner};
    struct task_struct stranger = {60, &init, &other, &other};
    struct task_struct admin = {70, &init, &root, &root};
    test_runner = (struct runner_config){1001, 10, 1};
    const unsigned int read = WW_PTRACE_READ | WW_PTRACE_FSCREDS;
    struct {
        struct task_struct *caller, *target;
        unsigned int mode;
        int expected;
    } cases[] = {
        {&step, &orphan, read, -WW_EACCES},
        {&step, &orphan, WW_PTRACE_READ, -WW_EACCES},
        {&grandchild, &step, read, -WW_EACCES},
        {&orphan, &grandchild, read, -WW_EACCES},
        {&step, &orphan, WW_PTRACE_ATTACH | WW_PTRACE_FSCREDS, 0},
        {&step, &child, read, 0},
        {&step, &grandchild, read, 0},
        {&worker, &orphan, read, 0},
        {&worker, &grandchild, read, 0},
        {&admin, &orphan, read, 0},
        {&stranger, &orphan, read, 0},
        {&step, &stranger, read, 0},
    };
    for (unsigned int i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        caller = cases[i].caller;
        u64 ctx[] = {(u64)cases[i].target, cases[i].mode, 0};
        assert(runner_read_check(ctx) == cases[i].expected);
    }
    // A chain deeper than ANCESTORS is refused, one within it is not.
    struct task_struct chain[ANCESTORS + 1];
    for (int i = 0; i <= ANCESTORS; i++)
        chain[i] = (struct task_struct){100 + i, i ? &chain[i - 1] : &step,
                                        &runner, &runner};
    caller = &step;
    u64 deep[] = {(u64)&chain[ANCESTORS], read, 0};
    assert(runner_read_check(deep) == -WW_EACCES);
    u64 within[] = {(u64)&chain[ANCESTORS - 2], read, 0};
    assert(runner_read_check(within) == 0);
    // Disabled again, nothing is refused.
    test_runner.enabled = 0;
    u64 off[] = {(u64)&orphan, read, 0};
    assert(runner_read_check(off) == 0);
}

int main(void)
{
    activation_guards();
    runner_reads_rule();
    // The rule's coverage, for every mode bit, of runner and other callers.
    for (unsigned int mode = 0; mode < 0x20U; mode++) {
        for (unsigned int ids = 0; ids < 8; ids++) {
            unsigned int uid = ids & 1 ? 1001 : 1002;
            unsigned int fsuid = ids & 2 ? 1001 : 1002;
            unsigned int target = ids & 4 ? 1001 : 0;
            unsigned int caller = mode & WW_PTRACE_FSCREDS ? fsuid : uid;
            int expected = (mode & WW_PTRACE_READ) && !(mode & WW_PTRACE_ATTACH) &&
                caller == 1001 && target == 1001;
            assert(runner_read_covered(mode, uid, fsuid, target, 1001) == expected);
        }
    }
    const unsigned int types[] = {WW_IFREG, WW_IFDIR, 0020000U, 0010000U,
                                  0060000U, 0120000U, 0140000U};
    // Exhaust every permission/special-bit combination for all inode types,
    // both filesystems, owners/nonowners, and root/nonroot acting users.
    for (unsigned int t = 0; t < sizeof(types) / sizeof(types[0]); t++) {
        for (unsigned int bits = 0; bits < 010000U; bits++) {
            for (unsigned int same_device = 0; same_device < 2; same_device++) {
                for (unsigned int same_owner = 0; same_owner < 2; same_owner++) {
                    for (unsigned int root = 0; root < 2; root++) {
                        unsigned int uid = root ? 0 : 1000;
                        unsigned int owner = same_owner ? uid : 1001;
                        int expected = same_device && !same_owner && (bits & 2) &&
                            (types[t] == WW_IFREG ||
                             (types[t] == WW_IFDIR && !(bits & 01000)));
                        assert(world_write_denied(types[t] | bits, owner, uid,
                                                  same_device ? 42 : 43, 42)
                               == !!expected);
                    }
                }
            }
        }
    }
    return 0;
}

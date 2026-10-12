// SPDX-License-Identifier: (MIT OR Apache-2.0)
#include <assert.h>
// Exercise the actual entry-point activation guards without kernel helpers.
// Production compilation retains CO-RE; native mocks use ordinary addresses.
#define CORE
#define __builtin_preserve_access_index(address) (address)
#include "world_write.bpf.c"

static struct root_config test_config;
static unsigned int reads;

static void *lookup_config(void *map, const void *key)
{
    (void)map;
    assert(*(const u32 *)key == 0);
    return &test_config;
}

static long failed_read(void *destination, u32 size, const void *source)
{
    (void)destination;
    (void)size;
    (void)source;
    reads++;
    return -1;
}

static void activation_guards(void)
{
    map_lookup = lookup_config;
    probe_read = failed_read;
    u64 permission[] = {0, 2, 0};
    u64 open[] = {0, 0};
    u64 setattr[] = {0, 0, 0, 0};
    assert(world_write_permission(permission) == 0);
    assert(world_write_open(open) == 0);
    assert(world_write_file_permission(permission) == 0);
    assert(world_write_setattr(setattr) == 0);
    assert(reads == 0);

    test_config.enabled = 1;
    permission[2] = open[1] = setattr[3] = (u64)-1;
    assert(world_write_permission(permission) == -1);
    assert(world_write_open(open) == -1);
    assert(world_write_file_permission(permission) == -1);
    assert(world_write_setattr(setattr) == -1);
    assert(reads == 0);
}

int main(void)
{
    activation_guards();
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

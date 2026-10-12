// SPDX-License-Identifier: (MIT OR Apache-2.0)
#ifndef WORLD_WRITE_POLICY_H
#define WORLD_WRITE_POLICY_H

// Kernel mode bits, independent of libc's representation of stat structs.
#define WW_IFMT 00170000U
#define WW_IFREG 0100000U
#define WW_IFDIR 0040000U
#define WW_STICKY 0001000U
#define WW_OTHER_WRITE 0000002U
#define WW_EACCES 13

// Stop a user modifying another user's globally writable host files or
// non-sticky directories. Group membership and namespace-local uid zero do
// not grant an exemption. Compare kernel kuid values, never namespace ids.
static inline int world_write_denied(unsigned int mode, unsigned int owner,
                                     unsigned int fsuid, unsigned int device,
                                     unsigned int root_device)
{
    if (device != root_device || owner == fsuid || !(mode & WW_OTHER_WRITE))
        return 0;
    unsigned int type = mode & WW_IFMT;
    return type == WW_IFREG || (type == WW_IFDIR && !(mode & WW_STICKY));
}

#endif

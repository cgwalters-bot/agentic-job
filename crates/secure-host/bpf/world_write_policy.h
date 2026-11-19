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

// PTRACE_MODE_* of include/linux/ptrace.h.
#define WW_PTRACE_READ 0x01U
#define WW_PTRACE_ATTACH 0x02U
#define WW_PTRACE_FSCREDS 0x08U

// Whether the runner-read rule covers an access check: a read (never an
// attach, which Yama decides) by the runner's kuid, with the credentials the
// kernel compares for that mode, of another task of the runner's kuid.
// The caller's exemptions (Runner.Worker, ancestors) are decided after.
static inline int runner_read_covered(unsigned int mode, unsigned int caller_uid,
                                      unsigned int caller_fsuid,
                                      unsigned int target_uid,
                                      unsigned int runner)
{
    if (!(mode & WW_PTRACE_READ) || (mode & WW_PTRACE_ATTACH))
        return 0;
    unsigned int caller = (mode & WW_PTRACE_FSCREDS) ? caller_fsuid : caller_uid;
    return caller == runner && target_uid == runner;
}

#endif

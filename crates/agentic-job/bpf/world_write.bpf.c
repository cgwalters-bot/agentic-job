// SPDX-License-Identifier: (MIT OR Apache-2.0)
// One object, only modify-return security hooks, each OFF until its map
// enables it. No LSM dispatch dependency.
// These deliberately small BTF declarations are relocated by CO-RE: no
// hand-computed offsets, uid maps, supplementary-group loops or event logs.
#include "world_write_policy.h"

#define SEC(name) __attribute__((section(name), used))
#ifndef CORE
#define CORE __attribute__((preserve_access_index))
#endif
#define INLINE static __attribute__((always_inline)) inline
typedef unsigned int u32;
typedef unsigned long long u64;

struct kuid_t { u32 val; } CORE;
struct super_block { u32 s_dev; } CORE;
struct inode {
    unsigned short i_mode;
    struct kuid_t i_uid;
    struct super_block *i_sb;
} CORE;
struct cred { struct kuid_t uid; struct kuid_t fsuid; } CORE;
struct task_struct {
    int tgid;
    struct task_struct *real_parent;
    const struct cred *real_cred;
    const struct cred *cred;
} CORE;
struct file { unsigned int f_mode; struct inode *f_inode; } CORE;
struct dentry { struct inode *d_inode; } CORE;
struct iattr { unsigned int ia_valid; } CORE;

// BPF_MAP_TYPE_ARRAY, one entry. This is OFF until the bpftool loader writes
// enabled=1 with the root filesystem's kernel dev_t (major << 20 | minor).
// Userspace stat's st_dev must not be copied without that conversion.
struct root_config { u32 device; u32 enabled; };
struct {
    int (*type)[2];
    int (*max_entries)[1];
    u32 *key;
    struct root_config *value;
} root_fs SEC(".maps");

// Also OFF until `secure-host world-write --deny-runner-reads` writes
// enabled=1 with the runner's kuid and Runner.Worker's tgid (init pid
// namespace). The threat: a step reading the environment, and so the
// tokens, of a process another step of the same job left running. Yama
// decides only attaches, and hidepid does not separate one uid's tasks.
struct runner_config { u32 runner; u32 worker; u32 enabled; };
struct {
    int (*type)[2];
    int (*max_entries)[1];
    u32 *key;
    struct runner_config *value;
} runner_reads SEC(".maps");

// How far up from the target an ancestor is looked for; deeper is refused.
#define ANCESTORS 32

static void *(*map_lookup)(void *, const void *) = (void *)1;
static u64 (*current_pid_tgid)(void) = (void *)14;
static long (*probe_read)(void *, u32, const void *) = (void *)113;
static struct task_struct *(*current_task)(void) = (void *)158;

#define READ(dst, field) probe_read(&(dst), sizeof(dst), \
                                  __builtin_preserve_access_index(&(field)))

INLINE int enabled(void)
{
    u32 key = 0;
    struct root_config *config = map_lookup(&root_fs, &key);
    return config && config->enabled;
}

INLINE int deny(struct inode *inode)
{
    u32 key = 0;
    struct root_config *config = map_lookup(&root_fs, &key);
    if (!config || !config->enabled)
        return 0;
    struct super_block *sb = 0;
    const struct cred *cred = 0;
    unsigned short mode = 0;
    u32 device = 0, owner = 0, fsuid = 0;
    struct task_struct *task = current_task();
    // Read failure while enabled is a denial, not a policy bypass.
    if (!inode || READ(sb, inode->i_sb) || !sb ||
        READ(device, sb->s_dev) || READ(mode, inode->i_mode) ||
        READ(owner, inode->i_uid.val) || READ(cred, task->cred) || !cred ||
        READ(fsuid, cred->fsuid.val))
        return -WW_EACCES;
    return world_write_denied(mode, owner, fsuid, device, config->device)
        ? -WW_EACCES : 0;
}

// Tracing contexts contain arguments followed by the previous BPF return.
// Preserve any previous denial; zero runs the original security wrapper.
SEC("fmod_ret/security_inode_permission")
int world_write_permission(u64 *ctx)
{
    int ret = (int)ctx[2];
    // MAY_WRITE: regular-file access and parent-directory mutation access.
    return ret ? ret : ((enabled() && (ctx[1] & 2)) ? deny((void *)ctx[0]) : 0);
}

SEC("fmod_ret/security_file_open")
int world_write_open(u64 *ctx)
{
    int ret = (int)ctx[1];
    if (ret || !enabled())
        return ret;
    struct file *file = (void *)ctx[0];
    unsigned int mode = 0;
    struct inode *inode = 0;
    if (READ(mode, file->f_mode) || READ(inode, file->f_inode))
        return -WW_EACCES;
    // FMODE_WRITE: opening for write, even before any data is written.
    return (mode & 2) ? deny(inode) : 0;
}

SEC("fmod_ret/security_file_permission")
int world_write_file_permission(u64 *ctx)
{
    int ret = (int)ctx[2];
    if (ret || !enabled() || !(ctx[1] & 2))
        return ret;
    struct file *file = (void *)ctx[0];
    struct inode *inode = 0;
    if (READ(inode, file->f_inode))
        return -WW_EACCES;
    // Recheck writes through descriptors opened before policy activation.
    return deny(inode);
}

SEC("fmod_ret/security_inode_setattr")
int world_write_setattr(u64 *ctx)
{
    // security_inode_setattr(struct mnt_idmap *, struct dentry *,
    //                        struct iattr *): same signature in 6.12 and 7.0.
    int ret = (int)ctx[3];
    if (ret || !enabled())
        return ret;
    struct dentry *dentry = (void *)ctx[1];
    struct iattr *attr = (void *)ctx[2];
    unsigned int valid = 0;
    struct inode *inode = 0;
    if (READ(valid, attr->ia_valid) || READ(inode, dentry->d_inode))
        return -WW_EACCES;
    // ATTR_SIZE: truncate/ftruncate, including already-open descriptors.
    return (valid & 8) ? deny(inode) : 0;
}

// Whether the thread group TGID is a strict ancestor of TASK, by
// real_parent as Yama's task_is_descendant walks it. A failed read or a
// chain deeper than ANCESTORS counts as no.
INLINE int ancestor(struct task_struct *task, u32 tgid)
{
    for (int depth = 0; depth < ANCESTORS; depth++) {
        struct task_struct *parent = 0;
        int pid = 0;
        if (READ(parent, task->real_parent) || !parent || READ(pid, parent->tgid))
            return 0;
        if ((u32)pid == tgid)
            return 1;
        if (pid <= 1)
            return 0;
        task = parent;
    }
    return 0;
}

// security_ptrace_access_check(struct task_struct *child, unsigned int mode),
// reached only after the kernel's own uid check passed and never for the
// caller's own thread group. A process may still read its descendants, as
// Yama scope 1 lets it attach to them; an orphan has been reparented away
// from every later step. Runner.Worker reads every process's environment
// for RUNNER_TRACKING_ID to end the job's orphans, so it is exempt.
SEC("fmod_ret/security_ptrace_access_check")
int runner_read_check(u64 *ctx)
{
    int ret = (int)ctx[2];
    if (ret)
        return ret;
    u32 key = 0;
    struct runner_config *config = map_lookup(&runner_reads, &key);
    unsigned int mode = (unsigned int)ctx[1];
    if (!config || !config->enabled || !(mode & WW_PTRACE_READ) ||
        (mode & WW_PTRACE_ATTACH))
        return 0;
    struct task_struct *child = (void *)ctx[0];
    struct task_struct *task = current_task();
    const struct cred *cred = 0, *target = 0;
    u32 uid = 0, fsuid = 0, owner = 0;
    // Read failure while enabled is a denial, not a policy bypass; only
    // a caller that is not the runner's by either id is spared reading on.
    if (READ(cred, task->cred) || !cred || READ(uid, cred->uid.val) ||
        READ(fsuid, cred->fsuid.val))
        return -WW_EACCES;
    if (uid != config->runner && fsuid != config->runner)
        return 0;
    if (READ(target, child->real_cred) || !target ||
        READ(owner, target->uid.val))
        return -WW_EACCES;
    if (!runner_read_covered(mode, uid, fsuid, owner, config->runner))
        return 0;
    u32 tgid = (u32)(current_pid_tgid() >> 32);
    return (tgid == config->worker || ancestor(child, tgid)) ? 0 : -WW_EACCES;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";

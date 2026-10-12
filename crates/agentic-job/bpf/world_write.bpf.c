// SPDX-License-Identifier: (MIT OR Apache-2.0)
// One object, only modify-return security hooks. No LSM dispatch dependency.
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
struct cred { struct kuid_t fsuid; } CORE;
struct task_struct { const struct cred *cred; } CORE;
struct file { unsigned int f_mode; struct inode *f_inode; } CORE;
struct dentry { struct inode *d_inode; } CORE;
struct iattr { unsigned int ia_valid; } CORE;

// BPF_MAP_TYPE_ARRAY, one entry. This is OFF until a future loader writes
// enabled=1 with the root filesystem's kernel dev_t (major << 20 | minor).
// Userspace stat's st_dev must not be copied without that conversion.
struct root_config { u32 device; u32 enabled; };
struct {
    int (*type)[2];
    int (*max_entries)[1];
    u32 *key;
    struct root_config *value;
} root_fs SEC(".maps");

static void *(*map_lookup)(void *, const void *) = (void *)1;
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

char LICENSE[] SEC("license") = "Dual MIT/GPL";

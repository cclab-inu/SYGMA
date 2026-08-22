//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#ifndef __user
#define __user
#endif

char __license[] SEC("license") = "Dual MIT/GPL";

#define INIT_PROCESS -1

#define PHASE_INIT 0
#define PHASE_MAIN 1

#define __NR_sigreturn 15
#define __NR_sched_yield 24
#define __NR_futex 202
#define __NR_epoll_wait 232
#define __NR_ppoll 271

#define SYGMA_SIGTRAP 5
#define SYGMA_PTRACE_EVENT_SECCOMP 7
#define SYGMA_PTRACE_SECCOMP_EXIT_CODE \
    ((SYGMA_PTRACE_EVENT_SECCOMP << 8) | SYGMA_SIGTRAP)

enum {
    PROG_STAGE2_VERIFY = 0,
    PROG_COLLECT_MODE = 1,
    PROG_MAX
};

struct pid_mount_ns {
    __u32 mountns;
    __u32 pidns;
};

struct syscall_graph_key {
    __u32 mntns;
    __u32 pidns;
    __u32 from_syscall;
    __u32 phase;
};

struct syscall_graph_value {
    __u8 allowed_mask[45];
};

struct execution_value {
    __u8 comm[16];
    __u32 execution_time;
};

struct app_syscall_bin_key {
    __u64 cgroup_id;
    __u64 bucket;
};

struct app_syscall_count_key {
    __u64 cgroup_id;
    __u32 syscall_nr;
    __u32 padding;
};

struct app_syscall_meta_value {
    __u64 total;
    __u64 first_boottime_ns;
    __u64 last_boottime_ns;
    __u32 root_tgid;
    __u32 padding;
};

#define APP_SYSCALL_BUCKET_NS 100000ULL

struct process_state {
    __u32 prev_syscall;
    __u32 current_syscall;
    __u32 image_id;

    __u32 saved_prev_syscall;
    __u32 in_signal_handler;

    __u32 policy_state;
    __u32 policy_initialized;
};

enum policy_type {
    POLICY_TYPE_NONE = 0,
    POLICY_TYPE_STATE_MACHINE = 2,
};

enum route_counter_id {
    ROUTE_CONVENTIONAL_SIGKILL = 0,
    ROUTE_LSM_BPF = 1,
    ROUTE_PTRACE_NOTIFY = 2,
    ROUTE_COUNTER_MAX = 3,
};

struct policy_config_value {
    __u32 type;
    __u32 initial_state;
};

struct policy_state_rule_key {
    __u32 mntns;
    __u32 pidns;
    __u32 state;
};

struct policy_state_transition_key {
    __u32 mntns;
    __u32 pidns;
    __u32 state;
    __u32 syscall;
};

struct collection_graph_key {
    __u32 mntns;
    __u32 pidns;
    __u32 prev_syscall;
    __u32 phase;
};

struct collection_graph_value {
    __u8 allowed_mask[45];
};

struct observed_transition_key {
    __u32 mntns;
    __u32 pidns;
    __u32 from_syscall;
    __u32 to_syscall;
    __u32 phase;
};

struct observation_state {
    __u32 prev_syscall;
    __u32 saved_prev_syscall;
};

struct transition_check_key {
    __u32 mntns;
    __u32 pidns;
    __u32 phase;
};

enum lsm_hook_type {
    LSM_HOOK_NONE = 0,
    LSM_FILE_PERMISSION = 1,
    LSM_INODE_GETATTR = 2,
    LSM_SOCKET_SENDMSG = 3,
    LSM_SOCKET_RECVMSG = 4,
    LSM_FILE_ALLOC = 5,
    LSM_MMAP_FILE = 6,
    LSM_SOCKET_SETSOCKOPT = 7,
    LSM_FILE_IOCTL = 8,
    LSM_SOCKET_CREATE = 9,
    LSM_SOCKET_CONNECT = 10,
    LSM_SOCKET_SHUTDOWN = 11,
    LSM_SOCKET_BIND = 12,
    LSM_SOCKET_LISTEN = 13,
    LSM_SOCKET_GETSOCKNAME = 14,
    LSM_SOCKET_GETPEERNAME = 15,
    LSM_SOCKET_GETSOCKOPT = 16,
    LSM_BPRM_CHECK_SECURITY = 17,
    LSM_SEM_SEMOP = 18,
    LSM_MSG_MSG_ALLOC_SECURITY = 19,
    LSM_FILE_FCNTL = 20,
    LSM_FILE_LOCK = 21,
    LSM_INODE_PERMISSION = 22,
    LSM_PATH_TRUNCATE = 23,
    LSM_INODE_MKDIR = 24,
    LSM_PATH_CHMOD = 25,
    LSM_PATH_CHOWN = 26,
    LSM_SYSLOG = 27,
    LSM_TASK_FIX_SETUID = 28,
    LSM_TASK_FIX_SETGID = 29,
    LSM_TASK_SETPGID = 30,
    LSM_CAPABLE = 31,
    LSM_CAPSET = 32,
    LSM_PATH_MKNOD = 33,
    LSM_SB_STATFS = 34,
    LSM_TASK_SETSCHEDULER = 35,
    LSM_TASK_GETSCHEDULER = 36,
    LSM_SETTIME = 37,
    LSM_KERNEL_LOAD_DATA = 38,
    LSM_QUOTACTL = 39,
    LSM_INODE_SETXATTR = 40,
    LSM_INODE_LISTXATTR = 41,
    LSM_INODE_REMOVEXATTR = 42,
    LSM_INODE_UNLINK = 43,
    LSM_TASK_MOVEMEMORY = 44,
    LSM_PERF_EVENT_OPEN = 45,
    LSM_KERNEL_READ_FILE = 46,
    LSM_BPF = 47,
    LSM_MOVE_MOUNT = 48,
    LSM_FILE_RECEIVE = 49,
    LSM_INODE_GETXATTR = 50,
    LSM_INODE_LINK = 51,
    LSM_PATH_RENAME = 52,
};

#define LSM_SYSCALL_ROUTES(X) \
    X(read, __x64_sys_read, 0, LSM_FILE_PERMISSION, LSM_HOOK_NONE) \
    X(write, __x64_sys_write, 1, LSM_FILE_PERMISSION, LSM_HOOK_NONE) \
    X(stat, __x64_sys_newstat, 4, LSM_INODE_GETATTR, LSM_HOOK_NONE) \
    X(fstat, __x64_sys_newfstat, 5, LSM_INODE_GETATTR, LSM_HOOK_NONE) \
    X(lstat, __x64_sys_newlstat, 6, LSM_INODE_GETATTR, LSM_HOOK_NONE) \
    X(mmap, __x64_sys_mmap, 9, LSM_MMAP_FILE, LSM_HOOK_NONE) \
    X(ioctl, __x64_sys_ioctl, 16, LSM_FILE_IOCTL, LSM_HOOK_NONE) \
    X(pread64, __x64_sys_pread64, 17, LSM_FILE_PERMISSION, LSM_HOOK_NONE) \
    X(pwrite64, __x64_sys_pwrite64, 18, LSM_FILE_PERMISSION, LSM_HOOK_NONE) \
    X(pipe, __x64_sys_pipe, 22, LSM_FILE_ALLOC, LSM_HOOK_NONE) \
    X(shmat, __x64_sys_shmat, 30, LSM_MMAP_FILE, LSM_HOOK_NONE) \
    X(sendfile, __x64_sys_sendfile64, 40, LSM_FILE_PERMISSION, LSM_HOOK_NONE) \
    X(socket, __x64_sys_socket, 41, LSM_SOCKET_CREATE, LSM_HOOK_NONE) \
    X(connect, __x64_sys_connect, 42, LSM_SOCKET_CONNECT, LSM_HOOK_NONE) \
    X(accept, __x64_sys_accept, 43, LSM_FILE_ALLOC, LSM_HOOK_NONE) \
    X(sendto, __x64_sys_sendto, 44, LSM_SOCKET_SENDMSG, LSM_HOOK_NONE) \
    X(recvfrom, __x64_sys_recvfrom, 45, LSM_SOCKET_RECVMSG, LSM_HOOK_NONE) \
    X(sendmsg, __x64_sys_sendmsg, 46, LSM_SOCKET_SENDMSG, LSM_HOOK_NONE) \
    X(recvmsg, __x64_sys_recvmsg, 47, LSM_SOCKET_RECVMSG, LSM_HOOK_NONE) \
    X(shutdown, __x64_sys_shutdown, 48, LSM_SOCKET_SHUTDOWN, LSM_HOOK_NONE) \
    X(bind, __x64_sys_bind, 49, LSM_SOCKET_BIND, LSM_HOOK_NONE) \
    X(listen, __x64_sys_listen, 50, LSM_SOCKET_LISTEN, LSM_HOOK_NONE) \
    X(getsockname, __x64_sys_getsockname, 51, LSM_SOCKET_GETSOCKNAME, LSM_HOOK_NONE) \
    X(getpeername, __x64_sys_getpeername, 52, LSM_SOCKET_GETPEERNAME, LSM_HOOK_NONE) \
    X(socketpair, __x64_sys_socketpair, 53, LSM_SOCKET_CREATE, LSM_HOOK_NONE) \
    X(setsockopt, __x64_sys_setsockopt, 54, LSM_SOCKET_SETSOCKOPT, LSM_HOOK_NONE) \
    X(getsockopt, __x64_sys_getsockopt, 55, LSM_SOCKET_GETSOCKOPT, LSM_HOOK_NONE) \
    X(execve, __x64_sys_execve, 59, LSM_BPRM_CHECK_SECURITY, LSM_HOOK_NONE) \
    X(semop, __x64_sys_semop, 65, LSM_SEM_SEMOP, LSM_HOOK_NONE) \
    X(msgsnd, __x64_sys_msgsnd, 69, LSM_MSG_MSG_ALLOC_SECURITY, LSM_HOOK_NONE) \
    X(fcntl, __x64_sys_fcntl, 72, LSM_FILE_FCNTL, LSM_HOOK_NONE) \
    X(flock, __x64_sys_flock, 73, LSM_FILE_LOCK, LSM_HOOK_NONE) \
    X(truncate, __x64_sys_truncate, 76, LSM_INODE_PERMISSION, LSM_HOOK_NONE) \
    X(ftruncate, __x64_sys_ftruncate, 77, LSM_PATH_TRUNCATE, LSM_HOOK_NONE) \
    X(chdir, __x64_sys_chdir, 80, LSM_INODE_PERMISSION, LSM_HOOK_NONE) \
    X(fchdir, __x64_sys_fchdir, 81, LSM_INODE_PERMISSION, LSM_HOOK_NONE) \
    X(rename, __x64_sys_rename, 82, LSM_PATH_RENAME, LSM_HOOK_NONE) \
    X(mkdir, __x64_sys_mkdir, 83, LSM_INODE_MKDIR, LSM_HOOK_NONE) \
    X(rmdir, __x64_sys_rmdir, 84, LSM_INODE_PERMISSION, LSM_HOOK_NONE) \
    X(link, __x64_sys_link, 86, LSM_INODE_LINK, LSM_HOOK_NONE) \
    X(unlink, __x64_sys_unlink, 87, LSM_INODE_PERMISSION, LSM_HOOK_NONE) \
    X(symlink, __x64_sys_symlink, 88, LSM_INODE_PERMISSION, LSM_HOOK_NONE) \
    X(chmod, __x64_sys_chmod, 90, LSM_PATH_CHMOD, LSM_HOOK_NONE) \
    X(fchmod, __x64_sys_fchmod, 91, LSM_PATH_CHMOD, LSM_HOOK_NONE) \
    X(chown, __x64_sys_chown, 92, LSM_PATH_CHOWN, LSM_HOOK_NONE) \
    X(fchown, __x64_sys_fchown, 93, LSM_PATH_CHOWN, LSM_HOOK_NONE) \
    X(lchown, __x64_sys_lchown, 94, LSM_PATH_CHOWN, LSM_HOOK_NONE) \
    X(syslog, __x64_sys_syslog, 103, LSM_SYSLOG, LSM_HOOK_NONE) \
    X(setuid, __x64_sys_setuid, 105, LSM_TASK_FIX_SETUID, LSM_HOOK_NONE) \
    X(setgid, __x64_sys_setgid, 106, LSM_TASK_FIX_SETGID, LSM_HOOK_NONE) \
    X(setpgid, __x64_sys_setpgid, 109, LSM_TASK_SETPGID, LSM_HOOK_NONE) \
    X(setreuid, __x64_sys_setreuid, 113, LSM_TASK_FIX_SETUID, LSM_HOOK_NONE) \
    X(setregid, __x64_sys_setregid, 114, LSM_TASK_FIX_SETGID, LSM_HOOK_NONE) \
    X(setgroups, __x64_sys_setgroups, 116, LSM_CAPABLE, LSM_HOOK_NONE) \
    X(setresuid, __x64_sys_setresuid, 117, LSM_TASK_FIX_SETUID, LSM_HOOK_NONE) \
    X(setresgid, __x64_sys_setresgid, 119, LSM_TASK_FIX_SETGID, LSM_HOOK_NONE) \
    X(capset, __x64_sys_capset, 126, LSM_CAPSET, LSM_HOOK_NONE) \
    X(mknod, __x64_sys_mknod, 133, LSM_PATH_MKNOD, LSM_HOOK_NONE) \
    X(ustat, __x64_sys_ustat, 136, LSM_SB_STATFS, LSM_HOOK_NONE) \
    X(statfs, __x64_sys_statfs, 137, LSM_SB_STATFS, LSM_HOOK_NONE) \
    X(fstatfs, __x64_sys_fstatfs, 138, LSM_SB_STATFS, LSM_HOOK_NONE) \
    X(sched_setparam, __x64_sys_sched_setparam, 142, LSM_TASK_SETSCHEDULER, LSM_HOOK_NONE) \
    X(sched_getparam, __x64_sys_sched_getparam, 143, LSM_TASK_GETSCHEDULER, LSM_HOOK_NONE) \
    X(sched_setscheduler, __x64_sys_sched_setscheduler, 144, LSM_TASK_SETSCHEDULER, LSM_HOOK_NONE) \
    X(sched_getscheduler, __x64_sys_sched_getscheduler, 145, LSM_TASK_GETSCHEDULER, LSM_HOOK_NONE) \
    X(sched_rr_get_interval, __x64_sys_sched_rr_get_interval, 148, LSM_TASK_GETSCHEDULER, LSM_HOOK_NONE) \
    X(vhangup, __x64_sys_vhangup, 153, LSM_CAPABLE, LSM_HOOK_NONE) \
    X(pivot_root, __x64_sys_pivot_root, 155, LSM_CAPABLE, LSM_HOOK_NONE) \
    X(chroot, __x64_sys_chroot, 161, LSM_INODE_PERMISSION, LSM_HOOK_NONE) \
    X(acct, __x64_sys_acct, 163, LSM_CAPABLE, LSM_HOOK_NONE) \
    X(settimeofday, __x64_sys_settimeofday, 164, LSM_SETTIME, LSM_HOOK_NONE) \
    X(mount, __x64_sys_mount, 165, LSM_CAPABLE, LSM_HOOK_NONE) \
    X(umount2, __x64_sys_umount, 166, LSM_CAPABLE, LSM_HOOK_NONE) \
    X(swapon, __x64_sys_swapon, 167, LSM_CAPABLE, LSM_HOOK_NONE) \
    X(swapoff, __x64_sys_swapoff, 168, LSM_CAPABLE, LSM_HOOK_NONE) \
    X(reboot, __x64_sys_reboot, 169, LSM_CAPABLE, LSM_HOOK_NONE) \
    X(sethostname, __x64_sys_sethostname, 170, LSM_CAPABLE, LSM_HOOK_NONE) \
    X(setdomainname, __x64_sys_setdomainname, 171, LSM_CAPABLE, LSM_HOOK_NONE) \
    X(init_module, __x64_sys_init_module, 175, LSM_KERNEL_LOAD_DATA, LSM_HOOK_NONE) \
    X(delete_module, __x64_sys_delete_module, 176, LSM_CAPABLE, LSM_HOOK_NONE) \
    X(quotactl, __x64_sys_quotactl, 179, LSM_QUOTACTL, LSM_HOOK_NONE) \
    X(setxattr, __x64_sys_setxattr, 188, LSM_INODE_SETXATTR, LSM_HOOK_NONE) \
    X(lsetxattr, __x64_sys_lsetxattr, 189, LSM_INODE_SETXATTR, LSM_HOOK_NONE) \
    X(fsetxattr, __x64_sys_fsetxattr, 190, LSM_INODE_SETXATTR, LSM_HOOK_NONE) \
    X(getxattr, __x64_sys_getxattr, 191, LSM_INODE_GETXATTR, LSM_HOOK_NONE) \
    X(lgetxattr, __x64_sys_lgetxattr, 192, LSM_INODE_GETXATTR, LSM_HOOK_NONE) \
    X(fgetxattr, __x64_sys_fgetxattr, 193, LSM_INODE_GETXATTR, LSM_HOOK_NONE) \
    X(listxattr, __x64_sys_listxattr, 194, LSM_INODE_LISTXATTR, LSM_HOOK_NONE) \
    X(llistxattr, __x64_sys_llistxattr, 195, LSM_INODE_LISTXATTR, LSM_HOOK_NONE) \
    X(flistxattr, __x64_sys_flistxattr, 196, LSM_INODE_LISTXATTR, LSM_HOOK_NONE) \
    X(removexattr, __x64_sys_removexattr, 197, LSM_INODE_REMOVEXATTR, LSM_HOOK_NONE) \
    X(lremovexattr, __x64_sys_lremovexattr, 198, LSM_INODE_REMOVEXATTR, LSM_HOOK_NONE) \
    X(fremovexattr, __x64_sys_fremovexattr, 199, LSM_INODE_REMOVEXATTR, LSM_HOOK_NONE) \
    X(sched_setaffinity, __x64_sys_sched_setaffinity, 203, LSM_TASK_SETSCHEDULER, LSM_HOOK_NONE) \
    X(sched_getaffinity, __x64_sys_sched_getaffinity, 204, LSM_TASK_GETSCHEDULER, LSM_HOOK_NONE) \
    X(epoll_create, __x64_sys_epoll_create, 213, LSM_FILE_ALLOC, LSM_HOOK_NONE) \
    X(mq_open, __x64_sys_mq_open, 240, LSM_FILE_ALLOC, LSM_HOOK_NONE) \
    X(mq_unlink, __x64_sys_mq_unlink, 241, LSM_INODE_UNLINK, LSM_HOOK_NONE) \
    X(kexec_load, __x64_sys_kexec_load, 246, LSM_CAPABLE, LSM_KERNEL_LOAD_DATA) \
    X(inotify_init, __x64_sys_inotify_init, 253, LSM_FILE_ALLOC, LSM_HOOK_NONE) \
    X(inotify_add_watch, __x64_sys_inotify_add_watch, 254, LSM_INODE_PERMISSION, LSM_HOOK_NONE) \
    X(migrate_pages, __x64_sys_migrate_pages, 256, LSM_TASK_MOVEMEMORY, LSM_HOOK_NONE) \
    X(mkdirat, __x64_sys_mkdirat, 258, LSM_INODE_MKDIR, LSM_HOOK_NONE) \
    X(mknodat, __x64_sys_mknodat, 259, LSM_PATH_MKNOD, LSM_HOOK_NONE) \
    X(fchownat, __x64_sys_fchownat, 260, LSM_PATH_CHOWN, LSM_HOOK_NONE) \
    X(newfstatat, __x64_sys_newfstatat, 262, LSM_INODE_GETATTR, LSM_HOOK_NONE) \
    X(renameat, __x64_sys_renameat, 264, LSM_PATH_RENAME, LSM_HOOK_NONE) \
    X(linkat, __x64_sys_linkat, 265, LSM_INODE_LINK, LSM_HOOK_NONE) \
    X(symlinkat, __x64_sys_symlinkat, 266, LSM_INODE_PERMISSION, LSM_HOOK_NONE) \
    X(fchmodat, __x64_sys_fchmodat, 268, LSM_PATH_CHMOD, LSM_HOOK_NONE) \
    X(timerfd_create, __x64_sys_timerfd_create, 283, LSM_FILE_ALLOC, LSM_HOOK_NONE) \
    X(eventfd, __x64_sys_eventfd, 284, LSM_FILE_ALLOC, LSM_HOOK_NONE) \
    X(fallocate, __x64_sys_fallocate, 285, LSM_FILE_PERMISSION, LSM_HOOK_NONE) \
    X(accept4, __x64_sys_accept4, 288, LSM_FILE_ALLOC, LSM_HOOK_NONE) \
    X(eventfd2, __x64_sys_eventfd2, 290, LSM_FILE_ALLOC, LSM_HOOK_NONE) \
    X(epoll_create1, __x64_sys_epoll_create1, 291, LSM_FILE_ALLOC, LSM_HOOK_NONE) \
    X(pipe2, __x64_sys_pipe2, 293, LSM_FILE_ALLOC, LSM_HOOK_NONE) \
    X(inotify_init1, __x64_sys_inotify_init1, 294, LSM_FILE_ALLOC, LSM_HOOK_NONE) \
     \
     \
    X(fanotify_init, __x64_sys_fanotify_init, 300, LSM_FILE_ALLOC, LSM_HOOK_NONE) \
    X(open_by_handle_at, __x64_sys_open_by_handle_at, 304, LSM_FILE_ALLOC, LSM_HOOK_NONE) \
    X(finit_module, __x64_sys_finit_module, 313, LSM_KERNEL_READ_FILE, LSM_HOOK_NONE) \
    X(sched_setattr, __x64_sys_sched_setattr, 314, LSM_TASK_SETSCHEDULER, LSM_HOOK_NONE) \
    X(sched_getattr, __x64_sys_sched_getattr, 315, LSM_TASK_GETSCHEDULER, LSM_HOOK_NONE) \
    X(renameat2, __x64_sys_renameat2, 316, LSM_PATH_RENAME, LSM_HOOK_NONE) \
    X(memfd_create, __x64_sys_memfd_create, 319, LSM_FILE_ALLOC, LSM_HOOK_NONE) \
    X(kexec_file_load, __x64_sys_kexec_file_load, 320, LSM_CAPABLE, LSM_HOOK_NONE) \
    X(bpf, __x64_sys_bpf, 321, LSM_BPF, LSM_HOOK_NONE) \
    X(execveat, __x64_sys_execveat, 322, LSM_BPRM_CHECK_SECURITY, LSM_HOOK_NONE) \
    X(userfaultfd, __x64_sys_userfaultfd, 323, LSM_FILE_ALLOC, LSM_HOOK_NONE) \
    X(copy_file_range, __x64_sys_copy_file_range, 326, LSM_FILE_PERMISSION, LSM_HOOK_NONE) \
    X(statx, __x64_sys_statx, 332, LSM_INODE_GETATTR, LSM_HOOK_NONE) \
    X(open_tree, __x64_sys_open_tree, 428, LSM_FILE_ALLOC, LSM_HOOK_NONE) \
    X(move_mount, __x64_sys_move_mount, 429, LSM_CAPABLE, LSM_MOVE_MOUNT) \
    X(fsopen, __x64_sys_fsopen, 430, LSM_CAPABLE, LSM_HOOK_NONE) \
    X(fsmount, __x64_sys_fsmount, 432, LSM_CAPABLE, LSM_HOOK_NONE) \
    X(fspick, __x64_sys_fspick, 433, LSM_CAPABLE, LSM_HOOK_NONE) \
    X(pidfd_open, __x64_sys_pidfd_open, 434, LSM_FILE_ALLOC, LSM_HOOK_NONE) \
    X(pidfd_getfd, __x64_sys_pidfd_getfd, 438, LSM_FILE_RECEIVE, LSM_HOOK_NONE) \
    X(process_madvise, __x64_sys_process_madvise, 440, LSM_CAPABLE, LSM_HOOK_NONE) \
    X(mount_setattr, __x64_sys_mount_setattr, 442, LSM_CAPABLE, LSM_HOOK_NONE) \
    X(quotactl_fd, __x64_sys_quotactl_fd, 443, LSM_CAPABLE, LSM_QUOTACTL)

#define SIGKILL_SYSCALL_ROUTES(X) \
    X(clone, __x64_sys_clone, 56) \
    X(fork, __x64_sys_fork, 57) \
    X(vfork, __x64_sys_vfork, 58) \
    X(clone3, __x64_sys_clone3, 435)

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} enforcement_ready_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, ROUTE_COUNTER_MAX);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} route_counter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct process_state);
    __uint(max_entries, 10000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} process_state_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, PROG_MAX);
} prog_array SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct syscall_graph_key);
    __type(value, struct syscall_graph_value);
    __uint(max_entries, 100000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} syscall_graph_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct pid_mount_ns);
    __type(value, struct policy_config_value);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} policy_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct policy_state_rule_key);
    __type(value, struct syscall_graph_value);
    __uint(max_entries, 16384);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} policy_state_rule_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct policy_state_transition_key);
    __type(value, __u32);
    __uint(max_entries, 65536);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} policy_state_transition_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct pid_mount_ns);
    __type(value, struct execution_value);
    __uint(max_entries, 50000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} execution_time_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u32);
    __uint(max_entries, 10000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} app_cgroups SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 50000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} app_tids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct app_syscall_bin_key);
    __type(value, __u64);
    __uint(max_entries, 200000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} app_sc_bins SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct app_syscall_count_key);
    __type(value, __u64);
    __uint(max_entries, 50000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} app_sc_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct app_syscall_count_key);
    __type(value, __u64);
    __uint(max_entries, 50000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} app_sc_first_seen SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct app_syscall_meta_value);
    __uint(max_entries, 10000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} app_sc_meta SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct pid_mount_ns);
    __type(value, __u32);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} collection_mode_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct collection_graph_key);
    __type(value, struct collection_graph_value);
    __uint(max_entries, 150000);

    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} collection_graph_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct pt_regs);
} percpu_regs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct pid_mount_ns);
    __type(value, __u64);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pid_mount_ns_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct pid_mount_ns);
    __uint(max_entries, 10000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tid_to_namespace SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct observed_transition_key);
    __type(value, __u32);
    __uint(max_entries, 150000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} observed_transition_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct observed_transition_key);
    __type(value, __u32);
    __uint(max_entries, 100000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocked_history SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct transition_check_key);
    __type(value, __u64);
    __uint(max_entries, 128);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} transition_check_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct observation_state);
    __uint(max_entries, 10000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} observation_state_map SEC(".maps");

static __always_inline u32 check_comm(u8 a[], u8 file[]) {
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        if (a[i] != file[i]) return 0;
        if (a[i] == '\0') return 1;
    }
    return 1;
}

static __always_inline u32 getMntInum(struct task_struct *task) {
    return BPF_CORE_READ(task, nsproxy, mnt_ns, ns).inum;
}

static __always_inline u32 getPidInum(struct task_struct *task) {
    return BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns).inum;
}

static __always_inline __u32 syscall_to_bit_index(__u32 syscall_num) {
    if (syscall_num <= 334)
        return syscall_num;
    if (syscall_num >= 424 && syscall_num <= 448)
        return 335 + (syscall_num - 424);
    return 0xFFFFFFFF;
}

static __always_inline int set_syscall_bit(struct collection_graph_value *value, __u32 syscall_num) {
    __u32 bit_index = syscall_to_bit_index(syscall_num);
    if (bit_index == 0xFFFFFFFF || bit_index >= 360) {
        return -1;
    }

    __u32 byte_pos = bit_index >> 3;
    __u32 bit_offset = bit_index & 7;

    if (byte_pos > 44) {
        return -1;
    }

    __u32 byte_index = 44 - byte_pos;

    #pragma unroll
    for (__u32 i = 0; i < 45; i++) {
        if (i == byte_index) {
            value->allowed_mask[i] |= (1 << bit_offset);
            return 0;
        }
    }

    return -1;
}

static __always_inline __u32 get_current_phase(struct task_struct *task) {
    struct pid_mount_ns ns;
    ns.pidns = getPidInum(task);
    ns.mountns = getMntInum(task);

    struct execution_value *exec_value = bpf_map_lookup_elem(&execution_time_map, &ns);
    if (!exec_value) {
        return PHASE_INIT;
    }

    return (exec_value->execution_time == 0) ? PHASE_INIT : PHASE_MAIN;
}

static __always_inline int is_syscall_entry(struct pt_regs *regs) {
    s64 ax = (s64)regs->ax;

    if (ax == -38) {
        return 1;
    }

    return 0;
}

static __always_inline int is_seccomp_ptrace_event(struct pt_regs *ctx) {

    unsigned long exit_code = BPF_CORE_READ(ctx, di);
    return exit_code == SYGMA_PTRACE_SECCOMP_EXIT_CODE;
}

static __always_inline int is_async_bypass_syscall(__u32 syscall_nr) {
    switch (syscall_nr) {
    case __NR_sched_yield:
    case __NR_futex:
    case __NR_epoll_wait:
    case __NR_ppoll:
        return 1;
    default:
        return 0;
    }
}

static __always_inline int verify_transition_lsm(
    struct pid_mount_ns *ns,
    __u32 syscall_nr,
    __u32 phase,
    __u32 prev_syscall)
{
    struct syscall_graph_key graph_key = {
        .mntns = ns->mountns,
        .pidns = ns->pidns,
        .from_syscall = prev_syscall,
        .phase = phase,
    };

    struct syscall_graph_value *graph_value = bpf_map_lookup_elem(&syscall_graph_map, &graph_key);

    if (!graph_value) {
        return -1;
    }

    __u32 bit_index = syscall_to_bit_index(syscall_nr);

    if (bit_index == 0xFFFFFFFF || bit_index >= 360)
        return -1;

    __u32 byte_pos = bit_index >> 3;
    __u32 bit_offset = bit_index & 7;

    if (byte_pos >= 45) return 0;

    __u32 byte_index = 44 - byte_pos;
    __u8 byte_value;
    bpf_probe_read(&byte_value, sizeof(byte_value), &graph_value->allowed_mask[byte_index]);

    if (byte_value & (1 << (bit_offset & 7))) {
        return 0;
    }

    return -1;
}

static __always_inline int policy_mask_allows(
    const struct syscall_graph_value *value,
    __u32 syscall_nr)
{
    if (!value)
        return 0;

    __u32 bit_index = syscall_to_bit_index(syscall_nr);
    if (bit_index == 0xFFFFFFFF || bit_index >= 360)
        return 0;

    __u32 byte_pos = bit_index >> 3;
    if (byte_pos >= 45)
        return 0;

    __u32 byte_index = 44 - byte_pos;
    __u8 byte_value = 0;
    bpf_probe_read(&byte_value, sizeof(byte_value),
        &value->allowed_mask[byte_index]);
    return (byte_value & (1 << (bit_index & 7))) != 0;
}

static __always_inline int state_machine_policy_decision(
    const struct pid_mount_ns *ns,
    struct process_state *ps,
    const struct policy_config_value *config,
    __u32 syscall_nr)
{
    if (!ps->policy_initialized) {
        ps->policy_state = config->initial_state;
        ps->policy_initialized = 1;
    }

    struct policy_state_rule_key rule_key = {
        .mntns = ns->mountns,
        .pidns = ns->pidns,
        .state = ps->policy_state,
    };
    struct syscall_graph_value *rule =
        bpf_map_lookup_elem(&policy_state_rule_map, &rule_key);
    if (!policy_mask_allows(rule, syscall_nr))
        return -1;

    struct policy_state_transition_key transition_key = {
        .mntns = ns->mountns,
        .pidns = ns->pidns,
        .state = ps->policy_state,
        .syscall = syscall_nr,
    };
    __u32 *next_state =
        bpf_map_lookup_elem(&policy_state_transition_map, &transition_key);
    if (next_state)
        ps->policy_state = *next_state;

    return 0;
}

static __always_inline void increment_transition_counter(
    void *map,
    const struct observed_transition_key *key)
{
    __u32 *count = bpf_map_lookup_elem(map, key);
    if (count) {
        __sync_fetch_and_add(count, 1);
        return;
    }

    __u32 initial = 1;
    if (bpf_map_update_elem(map, key, &initial, BPF_NOEXIST) != 0) {

        count = bpf_map_lookup_elem(map, key);
        if (count)
            __sync_fetch_and_add(count, 1);
    }
}

static __always_inline void increment_transition_heartbeat(
    const struct pid_mount_ns *ns,
    __u32 phase)
{
    struct transition_check_key key = {
        .mntns = ns->mountns,
        .pidns = ns->pidns,
        .phase = phase,
    };
    __u64 *count = bpf_map_lookup_elem(&transition_check_count, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
        return;
    }

    __u64 initial = 1;
    if (bpf_map_update_elem(
            &transition_check_count, &key, &initial, BPF_NOEXIST) != 0) {
        count = bpf_map_lookup_elem(&transition_check_count, &key);
        if (count)
            __sync_fetch_and_add(count, 1);
    }
}

static __always_inline struct observation_state *get_observation_state(
    __u32 tid)
{
    struct observation_state *state =
        bpf_map_lookup_elem(&observation_state_map, &tid);
    if (state)
        return state;

    struct observation_state initial = {
        .prev_syscall = 500,
        .saved_prev_syscall = 500,
    };
    bpf_map_update_elem(&observation_state_map, &tid, &initial, BPF_NOEXIST);
    return bpf_map_lookup_elem(&observation_state_map, &tid);
}

static __always_inline void observe_init_transition(
    const struct pid_mount_ns *ns,
    __u32 tid,
    __u32 syscall_nr)
{
    struct observation_state *state = get_observation_state(tid);
    increment_transition_heartbeat(ns, PHASE_INIT);
    if (!state)
        return;

    struct observed_transition_key key = {
        .mntns = ns->mountns,
        .pidns = ns->pidns,
        .from_syscall = state->prev_syscall,
        .to_syscall = syscall_nr,
        .phase = PHASE_INIT,
    };
    increment_transition_counter(&observed_transition_map, &key);
    state->prev_syscall = syscall_nr;
}

static __always_inline void record_policy_miss(
    const struct pid_mount_ns *ns,
    __u32 from_syscall,
    __u32 syscall_nr,
    __u32 phase)
{
    struct observed_transition_key key = {
        .mntns = ns->mountns,
        .pidns = ns->pidns,
        .from_syscall = from_syscall,
        .to_syscall = syscall_nr,
        .phase = phase,
    };
    increment_transition_counter(&blocked_history, &key);
}

static __always_inline int Policy_Decision(
    struct pid_mount_ns *ns,
    struct process_state *ps,
    __u32 syscall_nr,
    __u32 phase)
{

    if (phase != PHASE_MAIN) {
        __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
        observe_init_transition(ns, tid, syscall_nr);
        int result = verify_transition_lsm(
            ns, syscall_nr, phase, ps->prev_syscall);
        if (result == 0) {
            ps->prev_syscall = syscall_nr;
        } else {
            record_policy_miss(
                ns, ps->prev_syscall, syscall_nr, phase);
        }
        return result;
    }

    struct policy_config_value *config =
        bpf_map_lookup_elem(&policy_config_map, ns);
    if (!config || config->type != POLICY_TYPE_STATE_MACHINE)
        return -1;

    return state_machine_policy_decision(ns, ps, config, syscall_nr);
}

static __always_inline int is_lsm_enforced_syscall(__u32 syscall_nr)
{
    switch (syscall_nr) {
#define LSM_ROUTE_CASE(name, symbol, nr, hook, alternate_hook) case nr:
        LSM_SYSCALL_ROUTES(LSM_ROUTE_CASE)
#undef LSM_ROUTE_CASE
        return 1;
    default:
        return 0;
    }
}

static __always_inline int is_sigkill_enforced_syscall(__u32 syscall_nr)
{
    switch (syscall_nr) {
#define SIGKILL_ROUTE_CASE(name, symbol, nr) case nr:
        SIGKILL_SYSCALL_ROUTES(SIGKILL_ROUTE_CASE)
#undef SIGKILL_ROUTE_CASE
        return 1;
    default:
        return 0;
    }
}

static __always_inline int dedicated_enforcement_ready(void)
{
    __u32 key = 0;
    __u32 *ready = bpf_map_lookup_elem(&enforcement_ready_map, &key);
    return ready && *ready == 1;
}

static __always_inline void count_policy_route(__u32 route)
{
    __u64 *counter = bpf_map_lookup_elem(&route_counter_map, &route);
    if (counter)
        (*counter)++;
}

static __always_inline int handle_lsm_syscall_entry(__u32 syscall_nr)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;

    if (!dedicated_enforcement_ready())
        return 0;

    struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
    if (!ps)
        return 0;

    struct task_struct *task = (void *)bpf_get_current_task_btf();
    if (!task)
        return 0;

    struct pid_mount_ns ns = {
        .pidns = getPidInum(task),
        .mountns = getMntInum(task),
    };

    __u32 *collection_mode = bpf_map_lookup_elem(&collection_mode_map, &ns);
    if (collection_mode && *collection_mode == 1)
        return 0;

    __u64 *ns_map_value = bpf_map_lookup_elem(&pid_mount_ns_map, &ns);
    if (!ns_map_value)
        return 0;
    if (*ns_map_value == 1) {
        __u64 time = bpf_ktime_get_boot_ns();
        *ns_map_value = time;
    }

    __u32 phase = get_current_phase(task);
    count_policy_route(ROUTE_LSM_BPF);
    Policy_Decision(&ns, ps, syscall_nr, phase);

    return 0;
}

static __always_inline int handle_sigkill_syscall_entry(__u32 syscall_nr)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;

    if (!dedicated_enforcement_ready())
        return 0;

    struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
    if (!ps)
        return 0;

    struct task_struct *task = (void *)bpf_get_current_task_btf();
    if (!task)
        return 0;

    struct pid_mount_ns ns = {
        .pidns = getPidInum(task),
        .mountns = getMntInum(task),
    };

    __u32 *collection_mode = bpf_map_lookup_elem(&collection_mode_map, &ns);
    if (collection_mode && *collection_mode == 1)
        return 0;

    __u64 *ns_map_value = bpf_map_lookup_elem(&pid_mount_ns_map, &ns);
    if (!ns_map_value)
        return 0;
    if (*ns_map_value == 1) {
        __u64 time = bpf_ktime_get_boot_ns();
        *ns_map_value = time;
    }

    __u32 phase = get_current_phase(task);
    count_policy_route(ROUTE_CONVENTIONAL_SIGKILL);
    Policy_Decision(&ns, ps, syscall_nr, phase);

    return 0;
}

SEC("kprobe/ptrace_notify")
int stage1_filter(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;

    struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);

    struct task_struct *task = (void *)bpf_get_current_task_btf();
    if (!task) return 0;

    struct pid_mount_ns ns;
    ns.pidns = getPidInum(task);
    ns.mountns = getMntInum(task);

    int seccomp_event = is_seccomp_ptrace_event(ctx);
    __u32 phase = get_current_phase(task);

    if (seccomp_event && phase == PHASE_INIT)
        return 0;

    __u32 *collection_mode = bpf_map_lookup_elem(&collection_mode_map, &ns);
    if (collection_mode && *collection_mode == 1) {

        bpf_map_update_elem(&tid_to_namespace, &tid, &ns, BPF_ANY);

        bpf_tail_call(ctx, &prog_array, PROG_COLLECT_MODE);
        return 0;
    }

    if (!ps) return 0;

    __u64 *ns_map_value = bpf_map_lookup_elem(&pid_mount_ns_map, &ns);
    if (!ns_map_value) return 0;
    if (*ns_map_value == 1) {
        __u64 time = bpf_ktime_get_boot_ns();
        *ns_map_value = time;
    }

    void *stack_base = BPF_CORE_READ(task, stack);
    if (!stack_base) return 0;

    unsigned long stack_top = (unsigned long)stack_base + 0x4000;
    void *regs_ptr = (void *)(stack_top - sizeof(struct pt_regs));

    u32 zero = 0;
    struct pt_regs *user_regs = bpf_map_lookup_elem(&percpu_regs, &zero);
    if (!user_regs) return 0;

    if (bpf_probe_read_kernel(user_regs, sizeof(*user_regs), regs_ptr) != 0) {
        return 0;
    }

    if (!seccomp_event && !is_syscall_entry(user_regs)) {
        return 0;
    }

    ps->current_syscall = (__u32)user_regs->orig_ax;

    if (phase == PHASE_MAIN && seccomp_event &&
        is_async_bypass_syscall(ps->current_syscall))
        return 0;

    if (ps->current_syscall == __NR_sigreturn && phase != PHASE_MAIN) {
        observe_init_transition(&ns, tid, __NR_sigreturn);
        if (verify_transition_lsm(
                &ns, __NR_sigreturn, phase, ps->prev_syscall) != 0) {
            record_policy_miss(
                &ns, ps->prev_syscall, __NR_sigreturn, phase);
        }

        struct observation_state *observation =
            bpf_map_lookup_elem(&observation_state_map, &tid);
        if (observation)
            observation->prev_syscall = observation->saved_prev_syscall;
        ps->prev_syscall = ps->saved_prev_syscall;
        ps->in_signal_handler = 0;

        return 0;
    }

    if (dedicated_enforcement_ready() &&
        (is_lsm_enforced_syscall(ps->current_syscall) ||
         is_sigkill_enforced_syscall(ps->current_syscall)))
        return 0;

    bpf_tail_call(ctx, &prog_array, PROG_STAGE2_VERIFY);
    return 0;
}

SEC("kprobe/ptrace_notify")
int stage2_verify(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;

    struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
    if (!ps) {
        return 0;
    }

    struct task_struct *task = (void *)bpf_get_current_task_btf();

    struct pid_mount_ns ns;
    ns.pidns = getPidInum(task);
    ns.mountns = getMntInum(task);

    __u32 phase = get_current_phase(task);

    count_policy_route(ROUTE_PTRACE_NOTIFY);
    int result = Policy_Decision(
        &ns, ps, ps->current_syscall, phase);

    return result == 0 ? 1 : 0;
}

SEC("kprobe/ptrace_notify")
int collect_syscalls(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;

    struct task_struct *task = (void *)bpf_get_current_task_btf();

    struct pid_mount_ns ns;
    ns.pidns = getPidInum(task);
    ns.mountns = getMntInum(task);

    bpf_map_update_elem(&tid_to_namespace, &tid, &ns, BPF_ANY);

    __u32 *collection_mode = bpf_map_lookup_elem(&collection_mode_map, &ns);
    if (!collection_mode || *collection_mode != 1) {
        return 0;
    }

    void *stack_base = BPF_CORE_READ(task, stack);
    if (!stack_base) return 0;

    unsigned long stack_top = (unsigned long)stack_base + 0x4000;
    void *regs_ptr = (void *)(stack_top - sizeof(struct pt_regs));

    u32 zero = 0;
    struct pt_regs *user_regs = bpf_map_lookup_elem(&percpu_regs, &zero);
    if (!user_regs) return 0;

    if (bpf_probe_read_kernel(user_regs, sizeof(*user_regs), regs_ptr) != 0) {
        return 0;
    }

    if (!is_seccomp_ptrace_event(ctx) && !is_syscall_entry(user_regs)) {
        return 0;
    }

    __u32 current_syscall = (__u32)user_regs->orig_ax;

    struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
    if (!ps) {
        struct process_state new_ps = {};
        new_ps.prev_syscall = 500;
        new_ps.current_syscall = current_syscall;
        new_ps.in_signal_handler = 0;
        new_ps.saved_prev_syscall = 500;
        bpf_map_update_elem(&process_state_map, &tid, &new_ps, BPF_ANY);

        ps = bpf_map_lookup_elem(&process_state_map, &tid);
        if (!ps)
            return 0;
    }

    ps->current_syscall = current_syscall;

    __u32 phase = get_current_phase(task);

    if (current_syscall == __NR_sigreturn) {

        struct collection_graph_key graph_key = {
            .mntns = ns.mountns,
            .pidns = ns.pidns,
            .prev_syscall = ps->prev_syscall,
            .phase = phase,
        };

        struct collection_graph_value *graph_value = bpf_map_lookup_elem(&collection_graph_map, &graph_key);

        if (!graph_value) {
            struct collection_graph_value new_value = {};
            __builtin_memset(&new_value, 0, sizeof(new_value));

            if (set_syscall_bit(&new_value, 15) == 0) {
                bpf_map_update_elem(&collection_graph_map, &graph_key, &new_value, BPF_ANY);
            }
        } else {
            set_syscall_bit(graph_value, 15);
        }

        ps->prev_syscall = ps->saved_prev_syscall;
        ps->in_signal_handler = 0;

        return 0;
    }

    __u32 prev_syscall = ps->prev_syscall;

    struct collection_graph_key graph_key = {
        .mntns = ns.mountns,
        .pidns = ns.pidns,
        .prev_syscall = prev_syscall,
        .phase = phase,
    };

    struct collection_graph_value *graph_value = bpf_map_lookup_elem(&collection_graph_map, &graph_key);

    if (!graph_value) {
        struct collection_graph_value new_value = {};
        __builtin_memset(&new_value, 0, sizeof(new_value));

        if (set_syscall_bit(&new_value, ps->current_syscall) == 0) {
            bpf_map_update_elem(&collection_graph_map, &graph_key, &new_value, BPF_ANY);
        }
    } else {
        set_syscall_bit(graph_value, ps->current_syscall);
    }

    ps->prev_syscall = ps->current_syscall;
    return 0;
}

#define GAP_LAUNCHER_COMM "gap-launch"

#define GAP_LAUNCHER_REAL_COMM "gap-launch.real"

SEC("kretprobe/sys_execve")
int kretprobe_execve(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;

    __u8 comm[16];
    bpf_get_current_comm(comm, 16);

    static const u8 launcher_comm[16] = GAP_LAUNCHER_COMM;
    static const u8 launcher_real_comm[16] = GAP_LAUNCHER_REAL_COMM;
    __u8 parent_comm[16] = {0};
    BPF_CORE_READ_INTO(&parent_comm, task, real_parent, comm);
    if (check_comm(parent_comm, (u8 *)launcher_comm) == 1 ||
        check_comm(parent_comm, (u8 *)launcher_real_comm) == 1) {
        u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
        u64 cgroup_id = bpf_get_current_cgroup_id();
        u32 registered = 1;
        bpf_map_update_elem(&app_cgroups, &cgroup_id, &registered, BPF_ANY);
        bpf_map_update_elem(&app_tids, &tid, &cgroup_id, BPF_ANY);
        struct app_syscall_meta_value init_meta = {0};
        init_meta.root_tgid = tid;
        bpf_map_update_elem(&app_sc_meta, &cgroup_id, &init_meta, BPF_NOEXIST);
    }

    struct pid_mount_ns ns;
    ns.mountns = getMntInum(task);
    ns.pidns = getPidInum(task);

    struct execution_value *exec_value = bpf_map_lookup_elem(&execution_time_map, &ns);
    if (!exec_value) return 0;

    if (exec_value->execution_time == 1) return 0;

    if (check_comm(comm, exec_value->comm) == 1) {
        u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
        struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
        if (ps) {
            ps->policy_state = 0;
            ps->policy_initialized = 0;
        }

        exec_value->execution_time = 1;
    }

    return 0;
}

SEC("tp/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx) {
    u32 parent_pid = ctx->parent_pid;
    u32 child_pid = ctx->child_pid;

    u64 *parent_cgroup = bpf_map_lookup_elem(&app_tids, &parent_pid);
    if (parent_cgroup) {
        bpf_map_update_elem(&app_tids, &child_pid, parent_cgroup, BPF_ANY);
    }

    struct process_state *parent_ps = bpf_map_lookup_elem(&process_state_map, &parent_pid);
    if (!parent_ps) {
        return 0;
    }

    struct pid_mount_ns *parent_ns = bpf_map_lookup_elem(&tid_to_namespace, &parent_pid);
    if (parent_ns) {

        struct pid_mount_ns ns_copy;
        ns_copy.mountns = parent_ns->mountns;
        ns_copy.pidns = parent_ns->pidns;

        bpf_map_update_elem(&tid_to_namespace, &child_pid, &ns_copy, BPF_ANY);
    }

    struct process_state child_ps;
    child_ps.image_id = parent_ps->image_id;
    child_ps.prev_syscall = 500;
    child_ps.current_syscall = 500;
    child_ps.saved_prev_syscall = 500;
    child_ps.in_signal_handler = 0;
    child_ps.policy_state = 0;
    child_ps.policy_initialized = 0;

    bpf_map_update_elem(&process_state_map, &child_pid, &child_ps, BPF_ANY);

    struct observation_state child_observation = {
        .prev_syscall = 500,
        .saved_prev_syscall = 500,
    };
    bpf_map_update_elem(
        &observation_state_map, &child_pid, &child_observation, BPF_ANY);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    (void)ctx;
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    bpf_map_delete_elem(&process_state_map, &tid);
    bpf_map_delete_elem(&tid_to_namespace, &tid);
    bpf_map_delete_elem(&observation_state_map, &tid);
    bpf_map_delete_elem(&app_tids, &tid);
    return 0;
}

SEC("tp/signal/signal_deliver")
int handle_signal_deliver(struct trace_event_raw_signal_deliver *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
    if (!ps) return 0;

    ps->saved_prev_syscall = ps->prev_syscall;

    ps->prev_syscall = 500;

    ps->in_signal_handler = 1;

    struct observation_state *observation = get_observation_state(tid);
    if (observation) {
        observation->saved_prev_syscall = observation->prev_syscall;
        observation->prev_syscall = 500;
    }

    return 0;
}

#define DEFINE_LSM_SYSCALL_KPROBE(name, symbol, nr, hook, alternate_hook) \
SEC("kprobe/" #symbol) \
int kprobe_sys_##name(struct pt_regs *ctx) \
{ \
    (void)ctx; \
    return handle_lsm_syscall_entry(nr); \
}

LSM_SYSCALL_ROUTES(DEFINE_LSM_SYSCALL_KPROBE)

#undef DEFINE_LSM_SYSCALL_KPROBE

#define DEFINE_SIGKILL_SYSCALL_KPROBE(name, symbol, nr) \
SEC("kprobe/" #symbol) \
int kprobe_sigkill_##name(struct pt_regs *ctx) \
{ \
    (void)ctx; \
    return handle_sigkill_syscall_entry(nr); \
}

SIGKILL_SYSCALL_ROUTES(DEFINE_SIGKILL_SYSCALL_KPROBE)

#undef DEFINE_SIGKILL_SYSCALL_KPROBE

SEC("raw_tracepoint/sys_enter")
int handle_app_syscall_enter(struct bpf_raw_tracepoint_args *ctx) {
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 *cgroup_id_ptr = bpf_map_lookup_elem(&app_tids, &tid);
    if (!cgroup_id_ptr)
        return 0;
    u64 cgroup_id = *cgroup_id_ptr;
    u32 syscall_nr = (u32)ctx->args[1];
    u64 now = bpf_ktime_get_boot_ns();

    struct app_syscall_bin_key bin_key = {
        .cgroup_id = cgroup_id,
        .bucket = now / APP_SYSCALL_BUCKET_NS,
    };
    u64 *bin_count = bpf_map_lookup_elem(&app_sc_bins, &bin_key);
    if (bin_count) {
        __sync_fetch_and_add(bin_count, 1);
    } else {
        u64 one = 1;
        bpf_map_update_elem(&app_sc_bins, &bin_key, &one, BPF_ANY);
    }

    struct app_syscall_count_key count_key = {
        .cgroup_id = cgroup_id,
        .syscall_nr = syscall_nr,
        .padding = 0,
    };
    u64 *sc_count = bpf_map_lookup_elem(&app_sc_counts, &count_key);
    if (sc_count) {
        __sync_fetch_and_add(sc_count, 1);
    } else {
        u64 one = 1;
        bpf_map_update_elem(&app_sc_counts, &count_key, &one, BPF_ANY);
    }

    bpf_map_update_elem(&app_sc_first_seen, &count_key, &now, BPF_NOEXIST);

    struct app_syscall_meta_value *meta =
        bpf_map_lookup_elem(&app_sc_meta, &cgroup_id);
    if (meta) {
        if (meta->total == 0)
            meta->first_boottime_ns = now;
        meta->last_boottime_ns = now;
        __sync_fetch_and_add(&meta->total, 1);
    }

    return 0;
}

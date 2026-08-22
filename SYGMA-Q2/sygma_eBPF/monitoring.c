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
#define	EPERM 1
#define BUFSIZE 256
#define TX_THRESH 192
#define MAX_FILENAME_LEN 32
#define STR_MAX 31u
#define MAX_HUFFMAN_ENTRIES 256
#define MAX_COMPRESSED_SIZE 64
#define MAX_QUEUE_LEN 64

#define PHASE_INIT 0
#define PHASE_MAIN 1

/*
 * Availability evaluation mode: keep policy-miss accounting in
 * blocked_history, but never change the observed workload's behaviour.
 * Set to 0 for the normal enforcing build.
 */
#ifndef SYGMA_OBSERVATION_MODE
#define SYGMA_OBSERVATION_MODE 1
#endif

#define PID_SIZE_BIT    (1 << 0)
#define HUFFMAN_FLAG    (1 << 1)
#define ARG1_SIZE_SHIFT 2
#define ARG2_SIZE_SHIFT 4
#define ARG3_SIZE_SHIFT 6

#define MS_BITS(ts) ((ts) >> 24)
#define LS_BITS(ts) ((ts) & 0xFFFFFF)
#define TS_RECORD_MARKER (1ULL << 63)
#define IS_TS_RECORD(x) ((x) & TS_RECORD_MARKER)

#define __NR_clone 56
#define __NR_fork 57
#define __NR_execve 59
#define __NR_chmod 90
#define __NR_setuid 105
#define __NR_setgid 106
#define __NR_setreuid 113
#define __NR_mprotect 10
#define __NR_ptrace 101
#define __NR_socket 41
#define __NR_accept 43
#define __NR_bind 49
#define __NR_connect 42
#define __NR_listen 50
#define __NR_recvfrom 45
#define __NR_accept4 288
#define __NR_execveat 322
#define __NR_sigreturn 15
#define __NR_futex 202
#define __NR_sched_yield 24

#define CLONE_EN     'C'
#define FORK_EN      'F'
#define EXECVE_EN    'E'
#define EXECVEAT_EN  'T'
#define CHMOD_EN     'M'
#define SETUID_EN    'U'
#define SETGID_EN    'G'
#define SETREUID_EN  'D'
#define MPROTECT_EN  'P'
#define PTRACE_EN    'Y'
#define SOCKET_EN    'S'
#define ACCEPT_EN    'H'
#define BIND_EN      'B'
#define CONNECT_EN   'N'
#define LISTEN_EN    'L'
#define RECVFROM_EN  'R'
#define ACCEPT4_EN   'A'

#define TAIL_HUFFMAN_CLONE     26
#define TAIL_HUFFMAN_FORK      27
#define TAIL_HUFFMAN_EXECVE    28
#define TAIL_HUFFMAN_EXECVEAT  29
#define TAIL_HUFFMAN_CHMOD     30
#define TAIL_HUFFMAN_SETUID    31
#define TAIL_HUFFMAN_SETGID    32
#define TAIL_HUFFMAN_SETREUID  33
#define TAIL_HUFFMAN_MPROTECT  34
#define TAIL_HUFFMAN_PTRACE    35
#define TAIL_HUFFMAN_SOCKET    36
#define TAIL_HUFFMAN_ACCEPT    37
#define TAIL_HUFFMAN_BIND      38
#define TAIL_HUFFMAN_CONNECT   39
#define TAIL_HUFFMAN_LISTEN    40
#define TAIL_HUFFMAN_RECVFROM  41
#define TAIL_HUFFMAN_ACCEPT4   42

#define MAX_STRING_LEN 64

struct huffman_context {
    __u32 syscall_nr;
    __u8 syscall_name;
    __u8 arg_count;
    __u8 has_string;
    __u8 _padding;
    __u64 arg1;
    __u64 arg2;
    __u64 arg3;
    __u32 original_event_size;
    __u32 eaudit_event_size;
    __u32 pidns; 
    __u32 mntns;  
    char string_arg[MAX_STRING_LEN];
};

struct ns {
    __u32 mntns;
    __u32 pidns;
};

struct arg_key_1 {
    __u64 arg1;
};

struct arg_key_2 {
    __u64 arg1;
    __u64 arg2;
};

struct arg_key_3 {
    __u64 arg1;
    __u64 arg2;
    __u64 arg3;
};

struct compressed_data {
    __u8 valid;
    __u8 length;
    __u8 _padding[6];
    __u8 data[MAX_COMPRESSED_SIZE];
};

struct syscall_stats_key {
    __u32 pidns;
    __u32 mntns;
};

struct syscall_stats_value {
    __u64 enter_count;
    __u64 enqueued_count;
    __u64 dropped_count;
    __u64 batch_success;
    __u64 batch_failed;
    __u64 ringbuf_submit_count;  // ⭐ !
};

struct huffman_stats_key {
    __u32 pidns;
    __u32 mntns;
};

struct huffman_stats_value {
    __u64 compressed_count;
    __u64 total_saved_bytes;
    __u64 original_total_size;
    __u64 eaudit_total_size;
    __u64 huffman_total_size;
};

struct arg_key_string_1 {
    __u64 arg1;
    char str[MAX_STRING_LEN];
};

struct arg_key_string_2 {
    __u64 arg1;
    __u64 arg2;
    char str[MAX_STRING_LEN];
};

struct arg_key_string_3 {
    __u64 arg1;
    __u64 arg2;
    __u64 arg3;
    char str[MAX_STRING_LEN];
};

enum {
    PROG_STAGE2_VERIFY = 0,
    PROG_COLLECT_MODE = 1,
    PROG_MAX
};

struct event {
    u32 pid;
    u8 comm[16];
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

struct audit_b {
    __u32 idx;
    __u64 ts_msbs;
    __u32 event_count;
    __u8 data[BUFSIZE];
};

struct process_state {
    __u32 prev_syscall;
    __u32 current_syscall;
    __u32 image_id;

    __u32 saved_prev_syscall;
    __u32 in_signal_handler;
};

struct syscall_queue {
    __u32 syscalls[MAX_QUEUE_LEN];
    __u32 head;
    __u32 count;
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

struct container_info_key {
    __u32 pidns;
    __u32 mntns;
};

struct container_info_value {
    char name[64];  
};

struct blocked_syscall_key {
    __u32 mntns;
    __u32 pidns;
    __u32 from_syscall;
    __u32 to_syscall;
    __u32 phase;
};

/* Observation predecessor state, independent of process_state's prev_syscall
 * (which only advances on an allowed transition). Used so the full phase-0
 * transition graph can be captured for stability analysis even though the
 * enforcement decision may reject some of the same transitions. */
struct observation_state {
    __u32 prev_syscall;
    __u32 saved_prev_syscall;
};

/*
 * Positive evidence that an enforcement policy lookup was actually attempted.
 *
 * blocked_history alone cannot distinguish "no violations" from a broken
 * instrumentation path (missing namespace/process state, missing hook, etc.).
 * The availability evaluator snapshots this counter for the exact container
 * namespace and requires phase-0 to advance on every run.
 */
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

/*
 * Generated from output-effective-n-full-patched:
 * 146 certified LSM-E syscalls minus the four SIGKILL-priority syscalls.
 */
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
    X(perf_event_open, __x64_sys_perf_event_open, 298, LSM_PERF_EVENT_OPEN, LSM_HOOK_NONE) \
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

enum trigger_counter_type {
    TRIGGER_COUNTER_LSM = 0,
    TRIGGER_COUNTER_PTRACE = 1,
    TRIGGER_COUNTER_MAX = 2,
};

struct lsm_block_key {
    __u32 tid;
    __u32 lsm_hook_type;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct lsm_block_key);
    __type(value, __u32); 
    __uint(max_entries, 10000);
} lsm_block_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TRIGGER_COUNTER_MAX);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} trigger_counter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} enforcement_ready_map SEC(".maps");

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
    __type(value, struct execution_value);
    __uint(max_entries, 50000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} execution_time_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1000);
} policy_target_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct pid_mount_ns);
    __type(value, __u32);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ns_image_map SEC(".maps");

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
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} collection_graph_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct pid_mount_ns);  
    __type(value, __u32); 
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} main_process_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct audit_b);
} per_cpu_buffers SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct pt_regs);
} percpu_regs SEC(".maps");

struct syscall_key {
    __u32 pidns;
    __u32 mountns;
    __u32 syscall_num;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000); 
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, struct syscall_key);
    __type(value, __u64);  
} syscall_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

const struct event *unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_HUFFMAN_ENTRIES);
    __type(key, struct arg_key_1);
    __type(value, struct compressed_data);
} huffman_rules_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_HUFFMAN_ENTRIES);
    __type(key, struct arg_key_2);
    __type(value, struct compressed_data);
} huffman_rules_2 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_HUFFMAN_ENTRIES);
    __type(key, struct arg_key_3);
    __type(value, struct compressed_data);
} huffman_rules_3 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct huffman_context);
} huffman_context_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} huffman_enabled SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ns);
    __type(value, __u64);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pid_mount_ns_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct syscall_stats_key);
    __type(value, struct syscall_stats_value);
    __uint(max_entries, 128);
} syscall_stats_ns_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH); 
    __type(key, struct huffman_stats_key); 
    __type(value, struct huffman_stats_value);
    __uint(max_entries, 128);  
} huffman_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 50);
} prog_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_HUFFMAN_ENTRIES);
    __type(key, struct arg_key_string_1);
    __type(value, struct compressed_data);
} huffman_rules_str_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_HUFFMAN_ENTRIES);
    __type(key, struct arg_key_string_2);
    __type(value, struct compressed_data);
} huffman_rules_str_2 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_HUFFMAN_ENTRIES);
    __type(key, struct arg_key_string_3);
    __type(value, struct compressed_data);
} huffman_rules_str_3 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct container_info_key);
    __type(value, struct container_info_value);
    __uint(max_entries, 256);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} container_info_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct blocked_syscall_key);
    __type(value, __u32); 
    __uint(max_entries, 100000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocked_history SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); /* tid */
    __type(value, struct observation_state);
    __uint(max_entries, 50000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} observation_state_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct blocked_syscall_key);
    __type(value, __u32);
    __uint(max_entries, 300000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} observed_transition_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct transition_check_key);
    __type(value, __u64);
    __uint(max_entries, 4096);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} transition_check_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); 
    __type(value, struct pid_mount_ns); 
    __uint(max_entries, 10000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tid_to_namespace SEC(".maps");

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

static __always_inline void increment_enter_count_ns(__u32 pidns, __u32 mntns) {
    struct syscall_stats_key key = {
        .pidns = pidns,
        .mntns = mntns,
    };
    
    struct syscall_stats_value *stats = bpf_map_lookup_elem(&syscall_stats_ns_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->enter_count, 1);
    } else {
        struct syscall_stats_value new_stats = {
            .enter_count = 1,
            .enqueued_count = 0,
            .dropped_count = 0,
            .batch_success = 0,
            .batch_failed = 0,
            .ringbuf_submit_count = 0, 
        };
        bpf_map_update_elem(&syscall_stats_ns_map, &key, &new_stats, BPF_NOEXIST);
    }
}

static __always_inline int is_huffman_enabled(void) {
    __u32 key = 0;
    __u32 *enabled = bpf_map_lookup_elem(&huffman_enabled, &key);
    return (enabled && *enabled == 1);
}

static __always_inline __u32 calculate_original_size(__u32 syscall_nr, __u32 pid, __u64 arg1, __u64 arg2, __u64 arg3, __u8 arg_count) {
    __u32 size = 8;
    if (arg_count >= 1) size += 8;
    if (arg_count >= 2) size += 8;
    if (arg_count >= 3) size += 8;
    return size;
}

static __always_inline __u8 get_pid_size_bit(__u32 pid) {
    return (pid > 0xFFFF) ? 1 : 0; 
}

static __always_inline __u8 get_arg_size_bits(__u64 value) {
    if (value <= 0xFF) return 0;       
    if (value <= 0xFFFF) return 1;    
    if (value <= 0xFFFFFFFF) return 2; 
    return 3;                           
}

static __always_inline __u32 calculate_eaudit_size(__u32 pid, __u64 arg1, __u64 arg2, 
                                                    __u64 arg3, __u8 arg_count) {
    __u32 size = 6;
    
    size += (pid > 0xFFFF) ? 3 : 2;
    
    if (arg_count >= 1) {
        if (arg1 <= 0xFF) size += 1;
        else if (arg1 <= 0xFFFF) size += 2;
        else if (arg1 <= 0xFFFFFFFF) size += 4;
        else size += 8;
    }
    if (arg_count >= 2) {
        if (arg2 <= 0xFF) size += 1;
        else if (arg2 <= 0xFFFF) size += 2;
        else if (arg2 <= 0xFFFFFFFF) size += 4;
        else size += 8;
    }
    if (arg_count >= 3) {
        if (arg3 <= 0xFF) size += 1;
        else if (arg3 <= 0xFFFF) size += 2;
        else if (arg3 <= 0xFFFFFFFF) size += 4;
        else size += 8;
    }
    
    return size;
}

static __always_inline void encode_pid(struct audit_b *b, __u32 *idx, __u32 pid) {
    __u32 i = *idx;
    
    if (pid <= 0xFFFF) { 
        if (i + 2 <= BUFSIZE) {
            b->data[i++] = (pid >> 8) & 0xFF;
            b->data[i++] = pid & 0xFF;
        }
    } else { 
        if (i + 3 <= BUFSIZE) {
            b->data[i++] = (pid >> 16) & 0xFF;
            b->data[i++] = (pid >> 8) & 0xFF;
            b->data[i++] = pid & 0xFF;
        }
    }
    
    *idx = i;
}

static __always_inline void encode_arg(struct audit_b *b, __u32 *idx, __u64 value) {
    __u32 i = *idx;
    
    if (value <= 0xFF) {
        if (i < BUFSIZE) b->data[i++] = value & 0xFF;
    } else if (value <= 0xFFFF) {
        if (i + 2 <= BUFSIZE) {
            b->data[i++] = (value >> 8) & 0xFF;
            b->data[i++] = value & 0xFF;
        }
    } else if (value <= 0xFFFFFFFF) {
        if (i + 4 <= BUFSIZE) {
            b->data[i++] = (value >> 24) & 0xFF;
            b->data[i++] = (value >> 16) & 0xFF;
            b->data[i++] = (value >> 8) & 0xFF;
            b->data[i++] = value & 0xFF;
        }
    } else {
        if (i + 8 <= BUFSIZE) {
            #pragma unroll
            for (int j = 7; j >= 0; j--) {
                b->data[i++] = (value >> (j * 8)) & 0xFF;
            }
        }
    }
    
    *idx = i;
}

static __always_inline void add_args_0(struct audit_b *b, __u32 *idx, __u32 hdr) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    __u8 pid_bit = get_pid_size_bit(pid);
    b->data[hdr] = pid_bit;
    
    encode_pid(b, idx, pid);
}

static __always_inline void add_args_1(struct audit_b *b, __u32 *idx, __u32 hdr, __u64 arg1) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    __u8 pid_bit = get_pid_size_bit(pid);
    __u8 arg1_bits = get_arg_size_bits(arg1);
    
    b->data[hdr] = pid_bit | (arg1_bits << ARG1_SIZE_SHIFT);
    
    encode_pid(b, idx, pid);
    encode_arg(b, idx, arg1);
}

static __always_inline void add_args_2(struct audit_b *b, __u32 *idx, __u32 hdr, 
                                       __u64 arg1, __u64 arg2) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    __u8 pid_bit = get_pid_size_bit(pid);
    __u8 arg1_bits = get_arg_size_bits(arg1);
    __u8 arg2_bits = get_arg_size_bits(arg2);
    
    b->data[hdr] = pid_bit | (arg1_bits << ARG1_SIZE_SHIFT) | (arg2_bits << ARG2_SIZE_SHIFT);
    
    encode_pid(b, idx, pid);
    encode_arg(b, idx, arg1);
    encode_arg(b, idx, arg2);
}

static __always_inline void add_args_3(struct audit_b *b, __u32 *idx, __u32 hdr, __u64 arg1, __u64 arg2, __u64 arg3) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    __u8 pid_bit = get_pid_size_bit(pid);
    __u8 arg1_bits = get_arg_size_bits(arg1);
    __u8 arg2_bits = get_arg_size_bits(arg2);
    __u8 arg3_bits = get_arg_size_bits(arg3);
    
    b->data[hdr] = pid_bit | (arg1_bits << ARG1_SIZE_SHIFT) | 
                   (arg2_bits << ARG2_SIZE_SHIFT) | (arg3_bits << ARG3_SIZE_SHIFT);
    
    encode_pid(b, idx, pid);
    encode_arg(b, idx, arg1);
    encode_arg(b, idx, arg2);
    encode_arg(b, idx, arg3);
}

static __always_inline void add_huffman_data(struct audit_b *b, __u32 *idx, __u32 hdr,
                                              const struct compressed_data *comp_data) {
    if (!comp_data || comp_data->length == 0) return;
    
    __u32 i = *idx;
    
    if (i >= BUFSIZE - 67) return;
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (hdr >= BUFSIZE) return;
    
    __u8 pid_bit = get_pid_size_bit(pid);
    b->data[hdr] = pid_bit | HUFFMAN_FLAG;
    
    encode_pid(b, &i, pid);
    
    __u32 safe_base = i & (BUFSIZE - 1);
    
    __u32 copy_len = comp_data->length;
    if (copy_len > MAX_COMPRESSED_SIZE) copy_len = MAX_COMPRESSED_SIZE;
    
    #pragma unroll
    for (int j = 0; j < 64; j++) {
        if (j < copy_len) {
            __u32 safe_idx = (safe_base + j) & (BUFSIZE - 1);
            b->data[safe_idx] = comp_data->data[j & (MAX_COMPRESSED_SIZE - 1)];
        }
    }
    
    i += copy_len;
    if (i > BUFSIZE) i = BUFSIZE;
    
    *idx = i;
}

static __always_inline void update_huffman_stats_ns(
    __u32 pidns, __u32 mntns,
    __u64 compressed, int saved_bytes,
    __u32 original_size, __u32 eaudit_size, __u32 final_size)
{
    struct huffman_stats_key key = {
        .pidns = pidns,
        .mntns = mntns,
    };
    
    struct huffman_stats_value *stats = bpf_map_lookup_elem(&huffman_stats_map, &key);
    
    if (stats) {
        if (compressed) {
            __sync_fetch_and_add(&stats->compressed_count, 1);
            __sync_fetch_and_add(&stats->total_saved_bytes, saved_bytes);
        }
        __sync_fetch_and_add(&stats->original_total_size, original_size);
        __sync_fetch_and_add(&stats->eaudit_total_size, eaudit_size);
        __sync_fetch_and_add(&stats->huffman_total_size, final_size);
    } else {
        struct huffman_stats_value new_stats = {
            .compressed_count = compressed ? 1 : 0,
            .total_saved_bytes = compressed ? saved_bytes : 0,
            .original_total_size = original_size,
            .eaudit_total_size = eaudit_size,
            .huffman_total_size = final_size,
        };
        bpf_map_update_elem(&huffman_stats_map, &key, &new_stats, BPF_NOEXIST);
    }
}

static __always_inline void increment_ringbuf_submit_ns(__u32 pidns, __u32 mntns) {
    struct syscall_stats_key key = {
        .pidns = pidns,
        .mntns = mntns,
    };
    
    struct syscall_stats_value *stats = bpf_map_lookup_elem(&syscall_stats_ns_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->ringbuf_submit_count, 1);
    }
}

static __always_inline void check_xmit(struct audit_b* b, __u32 *idx, __u32 pidns, __u32 mntns) {
    if (!b || !idx) return;

    __u32 i = *idx;
    i &= (BUFSIZE - 1);
    *idx = i;

    __u64 now = bpf_ktime_get_boot_ns();
    __u64 current_ms = MS_BITS(now);
    
    if (i >= TX_THRESH || current_ms != b->ts_msbs) {
        __u64 ts_record = now | TS_RECORD_MARKER;
        bpf_ringbuf_output(&events, &ts_record, 8, 0);
        
        b->ts_msbs = current_ms;
        
        __u32 total_size = 20 + i;
        if (total_size > (20 + BUFSIZE)) return;
        
        bpf_ringbuf_output(&events, b, total_size, 0); 
        
        increment_ringbuf_submit_ns(pidns, mntns);

        *idx = 0;
        b->idx = 0;
        b->event_count = 0;
    }
}

static __always_inline struct audit_b* 
init_event(__u8 syscall_name, __u32 *idx, __u32 *hdr, __u32 pidns, __u32 mntns) {
    __u32 key = 0;
    struct audit_b *b = bpf_map_lookup_elem(&per_cpu_buffers, &key);
    if (!b) return NULL;
    
    if (b->idx >= BUFSIZE - 100) {
        check_xmit(b, &b->idx, pidns, mntns);
    }
    
    __u32 i = b->idx;
    if (i >= BUFSIZE - 100) return NULL;
    
    b->data[i++] = syscall_name;
    
    __u64 ts_ns = bpf_ktime_get_boot_ns();
    __u32 ts_ls = LS_BITS(ts_ns);
    b->data[i++] = (ts_ls >> 16) & 0xFF;
    b->data[i++] = (ts_ls >> 8) & 0xFF;
    b->data[i++] = ts_ls & 0xFF;
    
    *hdr = i;
    b->data[i++] = 0;
    
    *idx = i;
    return b;
}

static __always_inline void finish_event(struct audit_b *b, __u32 idx, __u32 pidns, __u32 mntns) {
    if (idx < BUFSIZE) {
        b->data[idx++] = '\n';
    }
    
    __sync_fetch_and_add(&b->event_count, 1);
    b->idx = idx;
}

static __always_inline int add_string_arg(struct audit_b *b, __u32 *idx, const char __user *str_ptr) {
    if (!str_ptr) {
        if (*idx < BUFSIZE) {
            b->data[*idx] = 0;
            (*idx)++;
        }
        return 0;
    }
    
    __u32 i = *idx;
    if (i + 17 > BUFSIZE) return 0;

    __u32 len_pos = i++;

    char buf[16];
    __builtin_memset(buf, 0, sizeof(buf));

    long ret = bpf_probe_read_user_str(buf, sizeof(buf), str_ptr);
    if (ret <= 0) {
        b->data[len_pos] = 0;
        *idx = i;
        return 0;
    }

    __u32 len = ret > 0 ? (__u32)ret - 1 : 0;
    if (len > 16) len = 16;

    b->data[len_pos] = (__u8)len;

    __u32 safe_base = i & (BUFSIZE - 1);
    
    #pragma unroll
    for (__u32 j = 0; j < 16; j++) {
        if (j < len) {
            __u32 safe_idx = (safe_base + j) & (BUFSIZE - 1);
            b->data[safe_idx] = buf[j];
        }
    }
    
    i += len;
    if (i > BUFSIZE) i = BUFSIZE;
    
    *idx = i;
    return 1;
}

static __always_inline int read_user_string(char *dst, const char __user *src, __u32 max_len) {
    if (!src || max_len > MAX_STRING_LEN) return 0;
    
    __builtin_memset(dst, 0, max_len);
    
    long ret = bpf_probe_read_user_str(dst, max_len, src);
    return (ret > 0) ? (ret - 1) : 0;
}

static __always_inline int is_syscall_entry(struct pt_regs *regs) {
    s64 ax = (s64)regs->ax;

    if (ax == -38) {
        return 1;
    }
    
    return 0;
}

static __always_inline int verify_transition_lsm(
    struct pid_mount_ns *ns,
    __u32 tid,
    __u32 syscall_nr,
    __u32 phase,
    __u32 prev_syscall,
    enum lsm_hook_type hook_type)
{
    struct syscall_graph_key graph_key = {
        .mntns = ns->mountns,
        .pidns = ns->pidns,
        .from_syscall = prev_syscall,
        .phase = phase,
    };
    
    struct syscall_graph_value *graph_value = bpf_map_lookup_elem(&syscall_graph_map, &graph_key);
    
    if (!graph_value) {
        if (hook_type != 0) {
            struct lsm_block_key block_key = {
                .tid = tid,
                .lsm_hook_type = hook_type,
            };
            bpf_map_update_elem(&lsm_block_map, &block_key, &syscall_nr, BPF_ANY);
        }
        return -1;  
    }
    
    __u32 bit_index = syscall_to_bit_index(syscall_nr);
    /*
     * A syscall outside the policy bitset is not implicitly allowed.  Treat
     * it as a policy miss so the availability experiment cannot report a
     * false zero merely because a newer syscall number is unrepresentable.
     */
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
    
    if (hook_type != 0) {
        struct lsm_block_key block_key = {
            .tid = tid,
            .lsm_hook_type = hook_type,
        };
        bpf_map_update_elem(&lsm_block_map, &block_key, &syscall_nr, BPF_ANY);
    }
    
    return -1;
}

static __always_inline void increment_trigger_counter(__u32 counter_type)
{
    __u64 *counter;

    if (counter_type >= TRIGGER_COUNTER_MAX)
        return;

    counter = bpf_map_lookup_elem(&trigger_counter_map, &counter_type);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    } else {
        __u64 initial = 1;
        bpf_map_update_elem(&trigger_counter_map, &counter_type, &initial, BPF_ANY);
    }
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

static __always_inline void clear_lsm_block(__u32 tid, enum lsm_hook_type hook_type)
{
    if (hook_type == LSM_HOOK_NONE)
        return;

    struct lsm_block_key key = {
        .tid = tid,
        .lsm_hook_type = hook_type,
    };
    bpf_map_delete_elem(&lsm_block_map, &key);
}

static __always_inline void arm_lsm_block(
    __u32 tid,
    __u32 syscall_nr,
    enum lsm_hook_type hook_type)
{
    if (hook_type == LSM_HOOK_NONE)
        return;

    struct lsm_block_key key = {
        .tid = tid,
        .lsm_hook_type = hook_type,
    };
    bpf_map_update_elem(&lsm_block_map, &key, &syscall_nr, BPF_ANY);
}

static __always_inline void clear_lsm_blocks_for_syscall(
    __u32 tid,
    __u32 syscall_nr,
    enum lsm_hook_type current_hook)
{
    clear_lsm_block(tid, current_hook);

    if (syscall_nr == 246) {
        clear_lsm_block(tid, LSM_CAPABLE);
        clear_lsm_block(tid, LSM_KERNEL_LOAD_DATA);
    } else if (syscall_nr == 429) {
        clear_lsm_block(tid, LSM_CAPABLE);
        clear_lsm_block(tid, LSM_MOVE_MOUNT);
    } else if (syscall_nr == 443) {
        clear_lsm_block(tid, LSM_CAPABLE);
        clear_lsm_block(tid, LSM_QUOTACTL);
    }
}

static __always_inline void record_blocked_transition(
    const struct pid_mount_ns *ns,
    __u32 from_syscall,
    __u32 to_syscall,
    __u32 phase)
{
    struct blocked_syscall_key history_key = {
        .mntns = ns->mountns,
        .pidns = ns->pidns,
        .from_syscall = from_syscall,
        .to_syscall = to_syscall,
        .phase = phase,
    };

    __u32 *count = bpf_map_lookup_elem(&blocked_history, &history_key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u32 initial = 1;
        bpf_map_update_elem(&blocked_history, &history_key, &initial, BPF_ANY);
    }
}

static __always_inline void record_transition_check(
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
    } else {
        __u64 initial = 1;
        bpf_map_update_elem(&transition_check_count, &key, &initial, BPF_NOEXIST);
    }
}

static __always_inline struct observation_state *get_observation_state(__u32 tid)
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
    __u32 syscall_nr,
    __u32 phase)
{
    if (phase != PHASE_INIT)
        return;

    struct observation_state *state = get_observation_state(tid);
    if (!state)
        return;

    struct blocked_syscall_key key = {
        .mntns = ns->mountns,
        .pidns = ns->pidns,
        .from_syscall = state->prev_syscall,
        .to_syscall = syscall_nr,
        .phase = phase,
    };
    __u32 *count = bpf_map_lookup_elem(&observed_transition_map, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u32 initial = 1;
        if (bpf_map_update_elem(&observed_transition_map, &key, &initial, BPF_NOEXIST) != 0) {
            count = bpf_map_lookup_elem(&observed_transition_map, &key);
            if (count)
                __sync_fetch_and_add(count, 1);
        }
    }
    state->prev_syscall = syscall_nr;
}

static __always_inline int handle_lsm_syscall_entry(
    __u32 syscall_nr,
    enum lsm_hook_type hook_type,
    enum lsm_hook_type alternate_hook_type)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;

    clear_lsm_block(tid, hook_type);
    clear_lsm_block(tid, alternate_hook_type);

    if (!dedicated_enforcement_ready())
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
        bpf_map_update_elem(&pid_mount_ns_map, &ns, &time, BPF_ANY);
    }

    struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
    if (!ps)
        return 0;

    __u32 previous_syscall = ps->prev_syscall;
    __u32 phase = get_current_phase(task);
    ps->current_syscall = syscall_nr;

    record_transition_check(&ns, phase);
    observe_init_transition(&ns, tid, syscall_nr, phase);
    increment_trigger_counter(TRIGGER_COUNTER_LSM);
    int result = verify_transition_lsm(
        &ns, tid, syscall_nr, phase, previous_syscall, hook_type);
    if (result < 0) {
        arm_lsm_block(tid, syscall_nr, alternate_hook_type);
        record_blocked_transition(&ns, previous_syscall, syscall_nr, phase);
    }

    ps->prev_syscall = syscall_nr;
    bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
    return 0;
}

static __always_inline int handle_sigkill_syscall_entry(__u32 syscall_nr)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;

    if (!dedicated_enforcement_ready())
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
        bpf_map_update_elem(&pid_mount_ns_map, &ns, &time, BPF_ANY);
    }

    struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
    if (!ps)
        return 0;

    __u32 previous_syscall = ps->prev_syscall;
    __u32 phase = get_current_phase(task);
    ps->current_syscall = syscall_nr;

    record_transition_check(&ns, phase);
    observe_init_transition(&ns, tid, syscall_nr, phase);
    int result = verify_transition_lsm(
        &ns, tid, syscall_nr, phase, previous_syscall, LSM_HOOK_NONE);
    if (result < 0) {
        record_blocked_transition(&ns, previous_syscall, syscall_nr, phase);
#if !SYGMA_OBSERVATION_MODE
        bpf_send_signal(9);
#endif
    }

    ps->prev_syscall = syscall_nr;
    bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
    return 0;
}

static __always_inline int enforce_pending_lsm_block(
    enum lsm_hook_type hook_type,
    int previous_ret)
{
    if (previous_ret != 0)
        return previous_ret;
    if (!dedicated_enforcement_ready())
        return 0;

    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    struct lsm_block_key key = {
        .tid = tid,
        .lsm_hook_type = hook_type,
    };

    __u32 *blocked_syscall = bpf_map_lookup_elem(&lsm_block_map, &key);
    if (!blocked_syscall)
        return 0;

    __u32 syscall_nr = *blocked_syscall;
    struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
    if (!ps || ps->current_syscall != syscall_nr) {
        clear_lsm_blocks_for_syscall(tid, syscall_nr, hook_type);
        return 0;
    }

    clear_lsm_blocks_for_syscall(tid, syscall_nr, hook_type);
#if SYGMA_OBSERVATION_MODE
    return 0;
#else
    return -EPERM;
#endif
}

// =============================================================================
// STAGE 1:   ( -  )
// =============================================================================

SEC("kprobe/ptrace_notify")
int stage1_filter(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    u8 comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
    
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    
    struct pid_mount_ns ns;
    ns.pidns = getPidInum(task);
    ns.mountns = getMntInum(task);
    
    // ⭐ Collection mode   TID→NS  
    __u32 *collection_mode = bpf_map_lookup_elem(&collection_mode_map, &ns);
    if (collection_mode && *collection_mode == 1) {
        // ⭐ Collection   TID 
        bpf_map_update_elem(&tid_to_namespace, &tid, &ns, BPF_ANY);
        
        bpf_tail_call(ctx, &prog_array, PROG_COLLECT_MODE);
        return 0;
    }

    if (!ps) return 0;

    __u64 *ns_map_value = bpf_map_lookup_elem(&pid_mount_ns_map, &ns);
    if (!ns_map_value) return 0;
    if (*ns_map_value == 1) {
        __u64 time = bpf_ktime_get_boot_ns();
        bpf_map_update_elem(&pid_mount_ns_map, &ns, &time, BPF_ANY);
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
    
    // ⭐ syscall entry  ( )
    if (!is_syscall_entry(user_regs)) {
        return 0;
    }
    __u32 phase = get_current_phase(task);
    
    ps->current_syscall = (__u32)user_regs->orig_ax;
    if (ps->current_syscall == __NR_futex || ps->current_syscall == __NR_sched_yield)
        return 0;
    // // ============== 🎯      ==============
    
    // // 1.  syscall 
    // if (phase == 1){
    //     __u32 *last_syscall_ptr = bpf_map_lookup_elem(&thread_last_syscall, &tid);
    //     __u32 last_syscall = last_syscall_ptr ? *last_syscall_ptr : 500;
        
    //     // ⭐ NEW: execve   syscall 500 
    //     if (ps->prev_syscall == 500) {
    //         last_syscall = 500;
    //     }
        
    //     // 2. syscall pair map 
    //     struct syscall_pair pair;
    //     pair.from_syscall = last_syscall;
    //     pair.to_syscall = ps->current_syscall;
    //     __u64 dummy = 1;
    //     bpf_map_update_elem(&syscall_transition_map, &pair, &dummy, BPF_ANY);
        
    //     // 3.   syscall 
    //     bpf_map_update_elem(&thread_last_syscall, &tid, &ps->current_syscall, BPF_ANY);
    // }
    // // ==============     ==============


    if (ps->current_syscall == __NR_sigreturn) {
        record_transition_check(&ns, phase);
        observe_init_transition(&ns, tid, __NR_sigreturn, phase);

        // ⭐ signal_deliver가 이 핸들러 진입을 잡지 못했다면(in_signal_handler==0)
        //    prev_syscall은 메인루프에서 넘어온 값이라 신뢰할 수 없다.
        //    예외루프는 설계상 항상 500(START)에서 시작하므로 그 값으로 대체한다.
        __u32 effective_from = ps->in_signal_handler ? ps->prev_syscall : 500;

        // 1. : "   (prev) -> 15"  ?
        struct syscall_graph_key graph_key;
        graph_key.mntns = ns.mountns;
        graph_key.pidns = ns.pidns;
        graph_key.from_syscall = effective_from;
        graph_key.phase = phase;

        struct syscall_graph_value *graph_value = bpf_map_lookup_elem(&syscall_graph_map, &graph_key);

        int allowed = 0;

        //   , 15
        if (graph_value) {
            __u32 bit_index = 15; // rt_sigreturn is 15
            __u32 byte_pos = bit_index >> 3;     // 1
            __u32 bit_offset = bit_index & 7;    // 7
            __u32 byte_index = 44 - byte_pos;    // 43

            if (graph_value->allowed_mask[byte_index] & (1 << bit_offset)) {
                allowed = 1;
            }
        }

        if (!allowed) {
            struct blocked_syscall_key history_key = {};
            history_key.mntns = ns.mountns;
            history_key.pidns = ns.pidns;
            history_key.from_syscall = effective_from;
            history_key.to_syscall = 15; //  15
            history_key.phase = phase;

            //    (Atomic)
            __u32 *count = bpf_map_lookup_elem(&blocked_history, &history_key);
            if (count) {
                __sync_fetch_and_add(count, 1);
            } else {
                __u32 initial = 1;
                bpf_map_update_elem(&blocked_history, &history_key, &initial, BPF_ANY);
            }

            // ⭐ in_signal_handler==0이면 saved_prev_syscall도 이번 건에 대해선
            //    신뢰할 수 없으므로 prev_syscall을 건드리지 않고 메인루프 위치를 보존한다.
            if (ps->in_signal_handler) {
                ps->prev_syscall = ps->saved_prev_syscall;
                struct observation_state *obs1 =
                    bpf_map_lookup_elem(&observation_state_map, &tid);
                if (obs1)
                    obs1->prev_syscall = obs1->saved_prev_syscall;
            }
            ps->in_signal_handler = 0; //
            bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);

            return 0;
        }

        if (ps->in_signal_handler) {
            ps->prev_syscall = ps->saved_prev_syscall;
            struct observation_state *obs2 =
                bpf_map_lookup_elem(&observation_state_map, &tid);
            if (obs2)
                obs2->prev_syscall = obs2->saved_prev_syscall;
        }
        ps->in_signal_handler = 0;

        bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
        return 0; // stage2    ( / )
    }
    
    struct syscall_key key = {
        .pidns = ns.pidns,
        .mountns = ns.mountns,
        .syscall_num = ps->current_syscall,
    };

    __u64 *count = bpf_map_lookup_elem(&syscall_stats, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 initial = 1;
        bpf_map_update_elem(&syscall_stats, &key, &initial, BPF_NOEXIST);
    }

    if (dedicated_enforcement_ready() &&
        (is_lsm_enforced_syscall(ps->current_syscall) ||
         is_sigkill_enforced_syscall(ps->current_syscall)))
        return 0;

    increment_trigger_counter(TRIGGER_COUNTER_PTRACE);
    bpf_tail_call(ctx, &prog_array, PROG_STAGE2_VERIFY);
    return 0;
}

// =============================================================================
// STAGE 2:   ( -  )
// =============================================================================

SEC("kprobe/ptrace_notify")
int stage2_verify(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    __u32 pid = pid_tgid >> 32;

    struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
    if (!ps) {
        return 0;
    }

    struct task_struct *task = (void *)bpf_get_current_task_btf();

    struct pid_mount_ns ns;
    ns.pidns = getPidInum(task);
    ns.mountns = getMntInum(task);

    __u32 phase = get_current_phase(task);

    // ⭐ 500   from_syscall 
    struct syscall_graph_key graph_key;
    graph_key.mntns = ns.mountns;
    graph_key.pidns = ns.pidns;
    graph_key.from_syscall = ps->prev_syscall;  // 500 !
    graph_key.phase = phase;
    bpf_printk("Verifying transition: from %d to %d in tid %d\n", ps->prev_syscall, ps->current_syscall, tid);

    record_transition_check(&ns, phase);
    observe_init_transition(&ns, tid, ps->current_syscall, phase);
    struct syscall_graph_value *graph_value = bpf_map_lookup_elem(&syscall_graph_map, &graph_key);
    if (!graph_value) {
        __u32 curr = ps->current_syscall;
        struct blocked_syscall_key history_key = {};
        history_key.mntns = ns.mountns;
        history_key.pidns = ns.pidns;
        history_key.from_syscall = ps->prev_syscall;
        history_key.to_syscall = ps->current_syscall; // ⭐   
        history_key.phase = phase;

        //   
        __u32 *count = bpf_map_lookup_elem(&blocked_history, &history_key);
        if (count) {
            __sync_fetch_and_add(count, 1); //  
        } else {
            __u32 initial = 1;
            bpf_map_update_elem(&blocked_history, &history_key, &initial, BPF_ANY);
        }
        
        ps->prev_syscall = ps->current_syscall;
        bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
        return 0;
    }
    
    __u32 bit_index = syscall_to_bit_index(ps->current_syscall);
    if (bit_index == 0xFFFFFFFF || bit_index >= 360) {
        record_blocked_transition(
            &ns, ps->prev_syscall, ps->current_syscall, phase);
        ps->prev_syscall = ps->current_syscall;
        bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
        return 0;
    }
    
    __u32 byte_pos = bit_index >> 3;
    __u32 bit_offset = bit_index & 7;
    
    if (byte_pos >= 45) {
        record_blocked_transition(
            &ns, ps->prev_syscall, ps->current_syscall, phase);
        ps->prev_syscall = ps->current_syscall;
        bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
        return 0;
    }
    
    __u32 byte_index = 44 - byte_pos;
    __u8 byte_value;
    bpf_probe_read(&byte_value, sizeof(byte_value), &graph_value->allowed_mask[byte_index]);

    if (byte_value & (1 << (bit_offset & 7))) {
        // 
        ps->prev_syscall = ps->current_syscall;
        bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
        return 1;
    }

    __u32 curr = ps->current_syscall;
    struct blocked_syscall_key history_key = {};
    history_key.mntns = ns.mountns;
    history_key.pidns = ns.pidns;
    history_key.from_syscall = ps->prev_syscall;
    history_key.to_syscall = ps->current_syscall; // ⭐   
    history_key.phase = phase;

    //   
    __u32 *count = bpf_map_lookup_elem(&blocked_history, &history_key);
    if (count) {
        __sync_fetch_and_add(count, 1); //  
    } else {
        __u32 initial = 1;
        bpf_map_update_elem(&blocked_history, &history_key, &initial, BPF_ANY);
    }
    ps->prev_syscall = ps->current_syscall;
    bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);

    return 0;
}

SEC("kprobe/ptrace_notify")
int collect_syscalls(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    __u8 comm[16];
    bpf_get_current_comm(comm, 16);

    struct task_struct *task = (void *)bpf_get_current_task_btf();

    struct pid_mount_ns ns;
    ns.pidns = getPidInum(task);
    ns.mountns = getMntInum(task);
    
    // ⭐ TID→NS  
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

    if (!is_syscall_entry(user_regs)) {
        return 0;
    }

    __u32 current_syscall = (__u32)user_regs->orig_ax;
    
    if (current_syscall == __NR_futex || current_syscall == __NR_sched_yield)
        return 0; 

    struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
    if (!ps) {
        struct process_state new_ps = {};
        new_ps.prev_syscall = 500; //  
        new_ps.current_syscall = current_syscall;
        new_ps.in_signal_handler = 0;
        new_ps.saved_prev_syscall = 500;
        bpf_map_update_elem(&process_state_map, &tid, &new_ps, BPF_ANY);
        
        ps = bpf_map_lookup_elem(&process_state_map, &tid);
        if (!ps) 
            return 0;
    }

    ps->current_syscall = current_syscall;

    bpf_printk("Verifying transition in initialization : from %d to %d in tid %d\n", ps->prev_syscall, ps->current_syscall, tid);

    // ⭐ Phase   ()
    __u32 phase = get_current_phase(task);

    if (current_syscall == __NR_sigreturn) {
        // ⭐ signal_deliver가 이 핸들러 진입을 잡지 못했다면 prev_syscall을 못 믿는다.
        //    예외루프는 설계상 항상 500(START)에서 시작하므로 그 값으로 대체한다.
        __u32 effective_from = ps->in_signal_handler ? ps->prev_syscall : 500;

        // 1. : "    -> 15"
        struct collection_graph_key graph_key = {
            .mntns = ns.mountns,
            .pidns = ns.pidns,
            .prev_syscall = effective_from,
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
            //
            if (set_syscall_bit(graph_value, 15) == 0) {
                bpf_map_update_elem(&collection_graph_map, &graph_key, graph_value, BPF_EXIST);
            }
        }

        // 2. :    (in_signal_handler==0이면 saved_prev_syscall도 못 믿으므로 보존)
        if (ps->in_signal_handler) {
            ps->prev_syscall = ps->saved_prev_syscall;
        }
        ps->in_signal_handler = 0;

        bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
        return 0; //
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
        //   
        if (set_syscall_bit(graph_value, ps->current_syscall) == 0) {
            bpf_map_update_elem(&collection_graph_map, &graph_key, graph_value, BPF_EXIST);
        }
    }

    // ⭐ process_state_map  ( )
    ps->prev_syscall = ps->current_syscall;
    bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);

    return 0;
}

// =============================================================================
// EXECVE  ( -  )
// =============================================================================

SEC("kretprobe/sys_execve")
int kretprobe_execve(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;
    
    __u8 comm[16];
    bpf_get_current_comm(comm, 16);
    
    struct pid_mount_ns ns;
    ns.mountns = getMntInum(task);
    ns.pidns = getPidInum(task);

    struct execution_value *exec_value = bpf_map_lookup_elem(&execution_time_map, &ns);
    if (!exec_value) return 0;
    
    // ✅  1  (stage1  )
    if (exec_value->execution_time == 1) return 0;
    bpf_printk("kretprobe_execve: execve detected for comm: %s\n", comm);
    // ⭐ Stage1    ( )
    if (check_comm(comm, exec_value->comm) == 1) {
        u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
        u32 pid = bpf_get_current_pid_tgid() >> 32;

        exec_value->execution_time = 1;
        bpf_map_update_elem(&execution_time_map, &ns, exec_value, BPF_ANY);
        bpf_map_update_elem(&main_process_map, &ns, &pid, BPF_ANY);

    }
    
    return 0;
}

SEC("tp/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx) {
    u32 parent_pid = ctx->parent_pid;
    struct process_state *parent_ps = bpf_map_lookup_elem(&process_state_map, &parent_pid);
    if (!parent_ps) {
        return 0;
    }

    u32 child_pid = ctx->child_pid;

    // ⭐ Parent namespace 
    struct pid_mount_ns *parent_ns = bpf_map_lookup_elem(&tid_to_namespace, &parent_pid);
    if (parent_ns) {
        // ✅   
        struct pid_mount_ns ns_copy;
        ns_copy.mountns = parent_ns->mountns;
        ns_copy.pidns = parent_ns->pidns;
        
        // ✅   
        bpf_map_update_elem(&tid_to_namespace, &child_pid, &ns_copy, BPF_ANY);
    }

    // ⭐ Child process state  (  )
    struct process_state child_ps;
    child_ps.image_id = parent_ps->image_id;
    child_ps.prev_syscall = 500;
    child_ps.current_syscall = 500;
    child_ps.saved_prev_syscall = 500;
    child_ps.in_signal_handler = 0;

    bpf_map_update_elem(&process_state_map, &child_pid, &child_ps, BPF_ANY);

    /* Only (re)seed the independent observation chain for namespaces still
     * in phase 0. observe_init_transition() never touches this map once a
     * namespace reaches PHASE_MAIN, so resetting it unconditionally here
     * left stale/never-advanced entries for every later (main-phase)
     * thread a workload forks, at whatever value they happened to hold
     * from this reset -- corrupting phase-0 edge attribution if that TID
     * number were ever (incorrectly) consulted again. */
    if (parent_ns) {
        struct execution_value *exec_value =
            bpf_map_lookup_elem(&execution_time_map, parent_ns);
        if (!exec_value || exec_value->execution_time == 0) {
            struct observation_state child_observation = {
                .prev_syscall = 500,
                .saved_prev_syscall = 500,
            };
            bpf_map_update_elem(
                &observation_state_map, &child_pid, &child_observation, BPF_ANY);
        }
    }
    return 0;
}

SEC("tp/signal/signal_deliver")
int handle_signal_deliver(struct trace_event_raw_signal_deliver *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
    if (!ps) return 0;

    ps->saved_prev_syscall = ps->prev_syscall;

    // 2.    (  !)
    ps->prev_syscall = 500;

    // 3.   ON
    ps->in_signal_handler = 1;

    bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);

    struct observation_state *observation = bpf_map_lookup_elem(&observation_state_map, &tid);
    if (observation) {
        observation->saved_prev_syscall = observation->prev_syscall;
        observation->prev_syscall = 500;
        bpf_map_update_elem(&observation_state_map, &tid, observation, BPF_ANY);
    }
    return 0;
}

// =============================================================================
// Dedicated enforcement entry probes
// =============================================================================

#define DEFINE_LSM_SYSCALL_KPROBE(name, symbol, nr, hook, alternate_hook) \
SEC("kprobe/" #symbol) \
int kprobe_sys_##name(struct pt_regs *ctx) \
{ \
    (void)ctx; \
    return handle_lsm_syscall_entry(nr, hook, alternate_hook); \
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

// =============================================================================
// LSM-BPF enforcement hooks
// =============================================================================

#if !SYGMA_OBSERVATION_MODE

#define DEFINE_LSM_ENFORCER(hook_name, hook_type, args...) \
SEC("lsm/" #hook_name) \
int BPF_PROG(lsm_##hook_name, args, int ret) \
{ \
    return enforce_pending_lsm_block(hook_type, ret); \
}

DEFINE_LSM_ENFORCER(bpf, LSM_BPF,
    int cmd, union bpf_attr *attr, unsigned int size)
DEFINE_LSM_ENFORCER(bprm_check_security, LSM_BPRM_CHECK_SECURITY,
    struct linux_binprm *bprm)
DEFINE_LSM_ENFORCER(capable, LSM_CAPABLE,
    const struct cred *cred, struct user_namespace *ns, int cap,
    unsigned int opts)
DEFINE_LSM_ENFORCER(capset, LSM_CAPSET,
    struct cred *new, const struct cred *old,
    const kernel_cap_t *effective, const kernel_cap_t *inheritable,
    const kernel_cap_t *permitted)
DEFINE_LSM_ENFORCER(file_alloc_security, LSM_FILE_ALLOC,
    struct file *file)
DEFINE_LSM_ENFORCER(file_fcntl, LSM_FILE_FCNTL,
    struct file *file, unsigned int cmd, unsigned long arg)
DEFINE_LSM_ENFORCER(file_ioctl, LSM_FILE_IOCTL,
    struct file *file, unsigned int cmd, unsigned long arg)
DEFINE_LSM_ENFORCER(file_lock, LSM_FILE_LOCK,
    struct file *file, unsigned int cmd)
DEFINE_LSM_ENFORCER(file_permission, LSM_FILE_PERMISSION,
    struct file *file, int mask)
DEFINE_LSM_ENFORCER(file_receive, LSM_FILE_RECEIVE,
    struct file *file)
DEFINE_LSM_ENFORCER(inode_getattr, LSM_INODE_GETATTR,
    const struct path *path)
DEFINE_LSM_ENFORCER(inode_getxattr, LSM_INODE_GETXATTR,
    struct dentry *dentry, const char *name)
DEFINE_LSM_ENFORCER(inode_link, LSM_INODE_LINK,
    struct dentry *old_dentry, struct inode *dir,
    struct dentry *new_dentry)
DEFINE_LSM_ENFORCER(inode_listxattr, LSM_INODE_LISTXATTR,
    struct dentry *dentry)
DEFINE_LSM_ENFORCER(inode_mkdir, LSM_INODE_MKDIR,
    struct inode *dir, struct dentry *dentry, umode_t mode)
DEFINE_LSM_ENFORCER(inode_permission, LSM_INODE_PERMISSION,
    struct inode *inode, int mask)
DEFINE_LSM_ENFORCER(inode_removexattr, LSM_INODE_REMOVEXATTR,
    struct user_namespace *mnt_userns, struct dentry *dentry,
    const char *name)
DEFINE_LSM_ENFORCER(inode_setxattr, LSM_INODE_SETXATTR,
    struct user_namespace *mnt_userns, struct dentry *dentry,
    const char *name, const void *value, size_t size, int flags)
DEFINE_LSM_ENFORCER(inode_unlink, LSM_INODE_UNLINK,
    struct inode *dir, struct dentry *dentry)
DEFINE_LSM_ENFORCER(kernel_load_data, LSM_KERNEL_LOAD_DATA,
    enum kernel_load_data_id id, bool contents)
DEFINE_LSM_ENFORCER(kernel_read_file, LSM_KERNEL_READ_FILE,
    struct file *file, enum kernel_read_file_id id, bool contents)
DEFINE_LSM_ENFORCER(mmap_file, LSM_MMAP_FILE,
    struct file *file, unsigned long reqprot, unsigned long prot,
    unsigned long flags)
DEFINE_LSM_ENFORCER(move_mount, LSM_MOVE_MOUNT,
    const struct path *from_path, const struct path *to_path)
DEFINE_LSM_ENFORCER(msg_msg_alloc_security, LSM_MSG_MSG_ALLOC_SECURITY,
    struct msg_msg *msg)
DEFINE_LSM_ENFORCER(path_chmod, LSM_PATH_CHMOD,
    const struct path *path, umode_t mode)
DEFINE_LSM_ENFORCER(path_mknod, LSM_PATH_MKNOD,
    const struct path *dir, struct dentry *dentry, umode_t mode,
    unsigned int dev)
DEFINE_LSM_ENFORCER(path_rename, LSM_PATH_RENAME,
    const struct path *old_dir, struct dentry *old_dentry,
    const struct path *new_dir, struct dentry *new_dentry)
DEFINE_LSM_ENFORCER(path_truncate, LSM_PATH_TRUNCATE,
    const struct path *path)
DEFINE_LSM_ENFORCER(perf_event_open, LSM_PERF_EVENT_OPEN,
    struct perf_event_attr *attr, int type)
DEFINE_LSM_ENFORCER(quotactl, LSM_QUOTACTL,
    int cmds, int type, int id, struct super_block *sb)
DEFINE_LSM_ENFORCER(sb_statfs, LSM_SB_STATFS,
    struct dentry *dentry)
DEFINE_LSM_ENFORCER(sem_semop, LSM_SEM_SEMOP,
    struct kern_ipc_perm *perm, struct sembuf *sops,
    unsigned int nsops, int alter)
DEFINE_LSM_ENFORCER(settime, LSM_SETTIME,
    const struct timespec64 *ts, const struct timezone *tz)
DEFINE_LSM_ENFORCER(socket_bind, LSM_SOCKET_BIND,
    struct socket *sock, struct sockaddr *address, int addrlen)
DEFINE_LSM_ENFORCER(socket_connect, LSM_SOCKET_CONNECT,
    struct socket *sock, struct sockaddr *address, int addrlen)
DEFINE_LSM_ENFORCER(socket_create, LSM_SOCKET_CREATE,
    int family, int type, int protocol, int kern)
DEFINE_LSM_ENFORCER(socket_getpeername, LSM_SOCKET_GETPEERNAME,
    struct socket *sock)
DEFINE_LSM_ENFORCER(socket_getsockname, LSM_SOCKET_GETSOCKNAME,
    struct socket *sock)
DEFINE_LSM_ENFORCER(socket_getsockopt, LSM_SOCKET_GETSOCKOPT,
    struct socket *sock, int level, int optname)
DEFINE_LSM_ENFORCER(socket_listen, LSM_SOCKET_LISTEN,
    struct socket *sock, int backlog)
DEFINE_LSM_ENFORCER(socket_recvmsg, LSM_SOCKET_RECVMSG,
    struct socket *sock, struct msghdr *msg, int size, int flags)
DEFINE_LSM_ENFORCER(socket_sendmsg, LSM_SOCKET_SENDMSG,
    struct socket *sock, struct msghdr *msg, int size)
DEFINE_LSM_ENFORCER(socket_setsockopt, LSM_SOCKET_SETSOCKOPT,
    struct socket *sock, int level, int optname)
DEFINE_LSM_ENFORCER(socket_shutdown, LSM_SOCKET_SHUTDOWN,
    struct socket *sock, int how)
DEFINE_LSM_ENFORCER(syslog, LSM_SYSLOG,
    int type)
DEFINE_LSM_ENFORCER(task_fix_setgid, LSM_TASK_FIX_SETGID,
    struct cred *new, const struct cred *old, int flags)
DEFINE_LSM_ENFORCER(task_fix_setuid, LSM_TASK_FIX_SETUID,
    struct cred *new, const struct cred *old, int flags)
DEFINE_LSM_ENFORCER(task_getscheduler, LSM_TASK_GETSCHEDULER,
    struct task_struct *task)
DEFINE_LSM_ENFORCER(task_movememory, LSM_TASK_MOVEMEMORY,
    struct task_struct *task)
DEFINE_LSM_ENFORCER(task_setpgid, LSM_TASK_SETPGID,
    struct task_struct *task, pid_t pgid)
DEFINE_LSM_ENFORCER(task_setscheduler, LSM_TASK_SETSCHEDULER,
    struct task_struct *task)

/*
 * Keep this hook typed like every other BPF LSM program.  A raw
 * unsigned-long-long context makes libbpf match arg1 against struct path and
 * is rejected on 5.15 kernels with "arg1 type STRUCT is unsupported".
 */
DEFINE_LSM_ENFORCER(path_chown, LSM_PATH_CHOWN,
    const struct path *path, kuid_t uid, kgid_t gid)

#undef DEFINE_LSM_ENFORCER

#endif /* !SYGMA_OBSERVATION_MODE */

// =============================================================================
// CLONE - 3  ( )
// =============================================================================

SEC("tracepoint/syscalls/sys_enter_clone")
int trace_clone_enter(struct trace_event_raw_sys_enter *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;

    __u32 pidns = getPidInum(task);
    __u32 mntns = getMntInum(task);
    struct ns pmns = {.pidns = pidns, .mntns = mntns};
    
    __u64 *is_valid = bpf_map_lookup_elem(&pid_mount_ns_map, &pmns);
    if (!is_valid) return 0;
    
    increment_enter_count_ns(pidns, mntns);
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    __u64 arg1 = ctx->args[0];
    __u64 arg2 = ctx->args[1];
    __u64 arg3 = ctx->args[2];
    
    __u32 hdr = 0;
    __u32 idx = 0;
    
    struct audit_b *b = init_event(CLONE_EN, &idx, &hdr, pidns, mntns);

    if (!b) return 0;
    
    __u32 original_size = calculate_original_size(__NR_clone, pid, arg1, arg2, arg3, 3);
    __u32 eaudit_size = calculate_eaudit_size(pid, arg1, arg2, arg3, 3);
    
    if (is_huffman_enabled()) {
        struct arg_key_3 arg_key = {
            .arg1 = arg1,
            .arg2 = arg2,
            .arg3 = arg3,
        };
        
        struct compressed_data *comp_data = bpf_map_lookup_elem(&huffman_rules_3, &arg_key);
        
        if (comp_data) {
            add_huffman_data(b, &idx, hdr, comp_data);
            
            __u32 pid_size = (pid > 0xFFFF) ? 3 : 2;
            __u32 huffman_event_size = 1 + 3 + 1 + pid_size + comp_data->length + 1;
            int saved_bytes = (int)eaudit_size - (int)huffman_event_size;
            
            update_huffman_stats_ns(pidns, mntns, 1, saved_bytes, 
                                   original_size, eaudit_size, huffman_event_size);
        } else {
            add_args_3(b, &idx, hdr, arg1, arg2, arg3);
            update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
        }
    } else {
        add_args_3(b, &idx, hdr, arg1, arg2, arg3);
        update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
    }
    
    finish_event(b, idx, pidns, mntns);
    return 0;
}

// =============================================================================
// FORK -   ( )
// =============================================================================

SEC("tracepoint/syscalls/sys_enter_fork")
int trace_fork_enter(struct trace_event_raw_sys_enter *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;

    __u32 pidns = getPidInum(task);
    __u32 mntns = getMntInum(task);
    struct ns pmns = {.pidns = pidns, .mntns = mntns};
    
    __u64 *is_valid = bpf_map_lookup_elem(&pid_mount_ns_map, &pmns);
    if (!is_valid) return 0;
    
    increment_enter_count_ns(pidns, mntns);
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    __u32 hdr = 0;
    __u32 idx = 0;
    
    struct audit_b *b = init_event(FORK_EN, &idx, &hdr, pidns, mntns);

    if (!b) return 0;
    
    add_args_0(b, &idx, hdr);
    
    __u32 original_size = calculate_original_size(__NR_fork, pid, 0, 0, 0, 0);
    __u32 eaudit_size = calculate_eaudit_size(pid, 0, 0, 0, 0);
    update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
    
    finish_event(b, idx, pidns, mntns);
    return 0;
}

// =============================================================================
// EXECVE - 3  +  ( )
// =============================================================================

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve_enter(struct trace_event_raw_sys_enter *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;

    __u32 pidns = getPidInum(task);
    __u32 mntns = getMntInum(task);
    struct ns pmns = {.pidns = pidns, .mntns = mntns};
    
    __u64 *is_valid = bpf_map_lookup_elem(&pid_mount_ns_map, &pmns);
    if (!is_valid) return 0;
    
    increment_enter_count_ns(pidns, mntns);
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    __u64 arg1 = ctx->args[0];
    __u64 arg2 = ctx->args[1];
    __u64 arg3 = ctx->args[2];
    const char __user *filename = (const char __user *)arg1;
    
    __u32 hdr = 0;
    __u32 idx = 0;
    
    struct audit_b *b = init_event(EXECVE_EN, &idx, &hdr, pidns, mntns);

    if (!b) return 0;
    
    __u32 original_size = calculate_original_size(__NR_execve, pid, arg1, arg2, arg3, 3);
    __u32 eaudit_size = calculate_eaudit_size(pid, arg1, arg2, arg3, 3);
    
    if (is_huffman_enabled()) {
        struct arg_key_string_3 arg_key = {};
        arg_key.arg1 = arg1;
        arg_key.arg2 = arg2;
        arg_key.arg3 = arg3;
        
        char string_arg[MAX_STRING_LEN];
        read_user_string(string_arg, filename, MAX_STRING_LEN);
        
        bpf_probe_read(arg_key.str, MAX_STRING_LEN, string_arg);
        
        struct compressed_data *comp_data = bpf_map_lookup_elem(&huffman_rules_str_3, &arg_key);
        
        if (comp_data) {
            add_huffman_data(b, &idx, hdr, comp_data);
            
            __u32 pid_size = (pid > 0xFFFF) ? 3 : 2;
            __u32 huffman_event_size = 1 + 3 + 1 + pid_size + comp_data->length + 1;
            int saved_bytes = (int)eaudit_size - (int)huffman_event_size;
            
            update_huffman_stats_ns(pidns, mntns, 1, saved_bytes,
                                   original_size, eaudit_size, huffman_event_size);
        } else {
            add_args_3(b, &idx, hdr, arg1, arg2, arg3);
            add_string_arg(b, &idx, filename);
            update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
        }
    } else {
        add_args_3(b, &idx, hdr, arg1, arg2, arg3);
        add_string_arg(b, &idx, filename);
        update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
    }
    
    finish_event(b, idx, pidns, mntns);
    return 0;
}

// =============================================================================
// EXECVEAT - 3  +  ( )
// =============================================================================

SEC("tracepoint/syscalls/sys_enter_execveat")
int trace_execveat_enter(struct trace_event_raw_sys_enter *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;

    __u32 pidns = getPidInum(task);
    __u32 mntns = getMntInum(task);
    struct ns pmns = {.pidns = pidns, .mntns = mntns};
    
    __u64 *is_valid = bpf_map_lookup_elem(&pid_mount_ns_map, &pmns);
    if (!is_valid) return 0;
    
    increment_enter_count_ns(pidns, mntns);
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    __u64 arg0 = ctx->args[0];
    __u64 arg1 = ctx->args[1];
    __u64 arg2 = ctx->args[2];
    const char __user *pathname = (const char __user *)arg1;
    
    __u32 hdr = 0;
    __u32 idx = 0;
    
    struct audit_b *b = init_event(EXECVEAT_EN, &idx, &hdr, pidns, mntns);

    if (!b) return 0;
    
    __u32 original_size = calculate_original_size(__NR_execveat, pid, arg0, arg1, arg2, 3);
    __u32 eaudit_size = calculate_eaudit_size(pid, arg0, arg1, arg2, 3);
    
    if (is_huffman_enabled()) {
        struct arg_key_string_3 arg_key = {};
        arg_key.arg1 = arg0;
        arg_key.arg2 = arg1;
        arg_key.arg3 = arg2;
        
        char string_arg[MAX_STRING_LEN];
        read_user_string(string_arg, pathname, MAX_STRING_LEN);
        
        bpf_probe_read(arg_key.str, MAX_STRING_LEN, string_arg);
        
        struct compressed_data *comp_data = bpf_map_lookup_elem(&huffman_rules_str_3, &arg_key);
        
        if (comp_data) {
            add_huffman_data(b, &idx, hdr, comp_data);
            
            __u32 pid_size = (pid > 0xFFFF) ? 3 : 2;
            __u32 huffman_event_size = 1 + 3 + 1 + pid_size + comp_data->length + 1;
            int saved_bytes = (int)eaudit_size - (int)huffman_event_size;
            
            update_huffman_stats_ns(pidns, mntns, 1, saved_bytes,
                                   original_size, eaudit_size, huffman_event_size);
        } else {
            add_args_3(b, &idx, hdr, arg0, arg1, arg2);
            add_string_arg(b, &idx, pathname);
            update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
        }
    } else {
        add_args_3(b, &idx, hdr, arg0, arg1, arg2);
        add_string_arg(b, &idx, pathname);
        update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
    }
    
    finish_event(b, idx, pidns, mntns);
    return 0;
}

// =============================================================================
// CHMOD - 2  +  ( )
// =============================================================================

SEC("tracepoint/syscalls/sys_enter_chmod")
int trace_chmod_enter(struct trace_event_raw_sys_enter *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;

    __u32 pidns = getPidInum(task);
    __u32 mntns = getMntInum(task);
    struct ns pmns = {.pidns = pidns, .mntns = mntns};
    
    __u64 *is_valid = bpf_map_lookup_elem(&pid_mount_ns_map, &pmns);
    if (!is_valid) return 0;
    
    increment_enter_count_ns(pidns, mntns);
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    __u64 arg0 = ctx->args[0];
    __u64 arg1 = ctx->args[1];
    const char __user *filename = (const char __user *)arg0;
    
    __u32 hdr = 0;
    __u32 idx = 0;
    
    struct audit_b *b = init_event(CHMOD_EN, &idx, &hdr, pidns, mntns);

    if (!b) return 0;
    
    __u32 original_size = calculate_original_size(__NR_chmod, pid, arg0, arg1, 0, 2);
    __u32 eaudit_size = calculate_eaudit_size(pid, arg0, arg1, 0, 2);
    
    if (is_huffman_enabled()) {
        struct arg_key_string_2 arg_key = {};
        arg_key.arg1 = arg0;
        arg_key.arg2 = arg1;
        
        char string_arg[MAX_STRING_LEN];
        read_user_string(string_arg, filename, MAX_STRING_LEN);
        
        bpf_probe_read(arg_key.str, MAX_STRING_LEN, string_arg);
        
        struct compressed_data *comp_data = bpf_map_lookup_elem(&huffman_rules_str_2, &arg_key);
        
        if (comp_data) {
            add_huffman_data(b, &idx, hdr, comp_data);
            
            __u32 pid_size = (pid > 0xFFFF) ? 3 : 2;
            __u32 huffman_event_size = 1 + 3 + 1 + pid_size + comp_data->length + 1;
            int saved_bytes = (int)eaudit_size - (int)huffman_event_size;
            
            update_huffman_stats_ns(pidns, mntns, 1, saved_bytes,
                                   original_size, eaudit_size, huffman_event_size);
        } else {
            add_args_2(b, &idx, hdr, arg0, arg1);
            add_string_arg(b, &idx, filename);
            update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
        }
    } else {
        add_args_2(b, &idx, hdr, arg0, arg1);
        add_string_arg(b, &idx, filename);
        update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
    }
    
    finish_event(b, idx, pidns, mntns);
    return 0;
}

// =============================================================================
// SETUID - 1  ( )
// =============================================================================

SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid_enter(struct trace_event_raw_sys_enter *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;

    __u32 pidns = getPidInum(task);
    __u32 mntns = getMntInum(task);
    struct ns pmns = {.pidns = pidns, .mntns = mntns};
    
    __u64 *is_valid = bpf_map_lookup_elem(&pid_mount_ns_map, &pmns);
    if (!is_valid) return 0;
    
    increment_enter_count_ns(pidns, mntns);
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 arg1 = ctx->args[0];
    
    __u32 hdr = 0;
    __u32 idx = 0;
    
    struct audit_b *b = init_event(SETUID_EN, &idx, &hdr, pidns, mntns);

    if (!b) return 0;
    
    __u32 original_size = calculate_original_size(__NR_setuid, pid, arg1, 0, 0, 1);
    __u32 eaudit_size = calculate_eaudit_size(pid, arg1, 0, 0, 1);
    
    if (is_huffman_enabled()) {
        struct arg_key_1 arg_key = { .arg1 = arg1 };
        struct compressed_data *comp_data = bpf_map_lookup_elem(&huffman_rules_1, &arg_key);
        
        if (comp_data) {
            add_huffman_data(b, &idx, hdr, comp_data);
            
            __u32 pid_size = (pid > 0xFFFF) ? 3 : 2;
            __u32 huffman_event_size = 1 + 3 + 1 + pid_size + comp_data->length + 1;
            int saved_bytes = (int)eaudit_size - (int)huffman_event_size;
            
            update_huffman_stats_ns(pidns, mntns, 1, saved_bytes,
                                   original_size, eaudit_size, huffman_event_size);
        } else {
            add_args_1(b, &idx, hdr, arg1);
            update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
        }
    } else {
        add_args_1(b, &idx, hdr, arg1);
        update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
    }
    
    finish_event(b, idx, pidns, mntns);
    return 0;
}

// =============================================================================
// SETGID - 1  ( )
// =============================================================================

SEC("tracepoint/syscalls/sys_enter_setgid")
int trace_setgid_enter(struct trace_event_raw_sys_enter *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;

    __u32 pidns = getPidInum(task);
    __u32 mntns = getMntInum(task);
    struct ns pmns = {.pidns = pidns, .mntns = mntns};
    
    __u64 *is_valid = bpf_map_lookup_elem(&pid_mount_ns_map, &pmns);
    if (!is_valid) return 0;
    
    increment_enter_count_ns(pidns, mntns);
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 arg1 = ctx->args[0];
    
    __u32 hdr = 0;
    __u32 idx = 0;
    
    struct audit_b *b = init_event(SETGID_EN, &idx, &hdr, pidns, mntns);

    if (!b) return 0;
    
    __u32 original_size = calculate_original_size(__NR_setgid, pid, arg1, 0, 0, 1);
    __u32 eaudit_size = calculate_eaudit_size(pid, arg1, 0, 0, 1);
    
    if (is_huffman_enabled()) {
        struct arg_key_1 arg_key = { .arg1 = arg1 };
        struct compressed_data *comp_data = bpf_map_lookup_elem(&huffman_rules_1, &arg_key);
        
        if (comp_data) {
            add_huffman_data(b, &idx, hdr, comp_data);
            
            __u32 pid_size = (pid > 0xFFFF) ? 3 : 2;
            __u32 huffman_event_size = 1 + 3 + 1 + pid_size + comp_data->length + 1;
            int saved_bytes = (int)eaudit_size - (int)huffman_event_size;
            
            update_huffman_stats_ns(pidns, mntns, 1, saved_bytes,
                                   original_size, eaudit_size, huffman_event_size);
        } else {
            add_args_1(b, &idx, hdr, arg1);
            update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
        }
    } else {
        add_args_1(b, &idx, hdr, arg1);
        update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
    }
    
    finish_event(b, idx, pidns, mntns);
    return 0;
}

// =============================================================================
// SETREUID - 2  ( )
// =============================================================================

SEC("tracepoint/syscalls/sys_enter_setreuid")
int trace_setreuid_enter(struct trace_event_raw_sys_enter *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;

    __u32 pidns = getPidInum(task);
    __u32 mntns = getMntInum(task);
    struct ns pmns = {.pidns = pidns, .mntns = mntns};
    
    __u64 *is_valid = bpf_map_lookup_elem(&pid_mount_ns_map, &pmns);
    if (!is_valid) return 0;
    
    increment_enter_count_ns(pidns, mntns);
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 arg1 = ctx->args[0];
    __u64 arg2 = ctx->args[1];
    
    __u32 hdr = 0;
    __u32 idx = 0;
    
    struct audit_b *b = init_event(SETREUID_EN, &idx, &hdr, pidns, mntns);

    if (!b) return 0;
    
    __u32 original_size = calculate_original_size(__NR_setreuid, pid, arg1, arg2, 0, 2);
    __u32 eaudit_size = calculate_eaudit_size(pid, arg1, arg2, 0, 2);
    
    if (is_huffman_enabled()) {
        struct arg_key_2 arg_key = {
            .arg1 = arg1,
            .arg2 = arg2,
        };
        struct compressed_data *comp_data = bpf_map_lookup_elem(&huffman_rules_2, &arg_key);
        
        if (comp_data) {
            add_huffman_data(b, &idx, hdr, comp_data);
            
            __u32 pid_size = (pid > 0xFFFF) ? 3 : 2;
            __u32 huffman_event_size = 1 + 3 + 1 + pid_size + comp_data->length + 1;
            int saved_bytes = (int)eaudit_size - (int)huffman_event_size;
            
            update_huffman_stats_ns(pidns, mntns, 1, saved_bytes,
                                   original_size, eaudit_size, huffman_event_size);
        } else {
            add_args_2(b, &idx, hdr, arg1, arg2);
            update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
        }
    } else {
        add_args_2(b, &idx, hdr, arg1, arg2);
        update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
    }
    
    finish_event(b, idx, pidns, mntns);
    return 0;
}

// =============================================================================
// MPROTECT, PTRACE, SOCKET, ACCEPT, BIND, CONNECT - 3  ( )
// =============================================================================

SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_mprotect_enter(struct trace_event_raw_sys_enter *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;

    __u32 pidns = getPidInum(task);
    __u32 mntns = getMntInum(task);
    struct ns pmns = {.pidns = pidns, .mntns = mntns};
    
    __u64 *is_valid = bpf_map_lookup_elem(&pid_mount_ns_map, &pmns);
    if (!is_valid) return 0;
    
    increment_enter_count_ns(pidns, mntns);
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 arg1 = ctx->args[0];
    __u64 arg2 = ctx->args[1];
    __u64 arg3 = ctx->args[2];
    
    __u32 hdr = 0;
    __u32 idx = 0;
    
    struct audit_b *b = init_event(MPROTECT_EN, &idx, &hdr, pidns, mntns);

    if (!b) return 0;
    
    __u32 original_size = calculate_original_size(__NR_mprotect, pid, arg1, arg2, arg3, 3);
    __u32 eaudit_size = calculate_eaudit_size(pid, arg1, arg2, arg3, 3);
    
    if (is_huffman_enabled()) {
        struct arg_key_3 arg_key = {
            .arg1 = arg1,
            .arg2 = arg2,
            .arg3 = arg3,
        };
        struct compressed_data *comp_data = bpf_map_lookup_elem(&huffman_rules_3, &arg_key);
        
        if (comp_data) {
            add_huffman_data(b, &idx, hdr, comp_data);
            
            __u32 pid_size = (pid > 0xFFFF) ? 3 : 2;
            __u32 huffman_event_size = 1 + 3 + 1 + pid_size + comp_data->length + 1;
            int saved_bytes = (int)eaudit_size - (int)huffman_event_size;
            
            update_huffman_stats_ns(pidns, mntns, 1, saved_bytes,
                                   original_size, eaudit_size, huffman_event_size);
        } else {
            add_args_3(b, &idx, hdr, arg1, arg2, arg3);
            update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
        }
    } else {
        add_args_3(b, &idx, hdr, arg1, arg2, arg3);
        update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
    }
    
    finish_event(b, idx, pidns, mntns);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace_enter(struct trace_event_raw_sys_enter *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;

    __u32 pidns = getPidInum(task);
    __u32 mntns = getMntInum(task);
    struct ns pmns = {.pidns = pidns, .mntns = mntns};
    
    __u64 *is_valid = bpf_map_lookup_elem(&pid_mount_ns_map, &pmns);
    if (!is_valid) return 0;
    
    increment_enter_count_ns(pidns, mntns);
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 arg1 = ctx->args[0];
    __u64 arg2 = ctx->args[1];
    __u64 arg3 = ctx->args[2];
    
    __u32 hdr = 0;
    __u32 idx = 0;
    
    struct audit_b *b = init_event(PTRACE_EN, &idx, &hdr, pidns, mntns);

    if (!b) return 0;
    
    __u32 original_size = calculate_original_size(__NR_ptrace, pid, arg1, arg2, arg3, 3);
    __u32 eaudit_size = calculate_eaudit_size(pid, arg1, arg2, arg3, 3);
    
    if (is_huffman_enabled()) {
        struct arg_key_3 arg_key = {
            .arg1 = arg1,
            .arg2 = arg2,
            .arg3 = arg3,
        };
        struct compressed_data *comp_data = bpf_map_lookup_elem(&huffman_rules_3, &arg_key);
        
        if (comp_data) {
            add_huffman_data(b, &idx, hdr, comp_data);
            
            __u32 pid_size = (pid > 0xFFFF) ? 3 : 2;
            __u32 huffman_event_size = 1 + 3 + 1 + pid_size + comp_data->length + 1;
            int saved_bytes = (int)eaudit_size - (int)huffman_event_size;
            
            update_huffman_stats_ns(pidns, mntns, 1, saved_bytes,
                                   original_size, eaudit_size, huffman_event_size);
        } else {
            add_args_3(b, &idx, hdr, arg1, arg2, arg3);
            update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
        }
    } else {
        add_args_3(b, &idx, hdr, arg1, arg2, arg3);
        update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
    }
    
    finish_event(b, idx, pidns, mntns);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_socket")
int trace_socket_enter(struct trace_event_raw_sys_enter *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;

    __u32 pidns = getPidInum(task);
    __u32 mntns = getMntInum(task);
    struct ns pmns = {.pidns = pidns, .mntns = mntns};
    
    __u64 *is_valid = bpf_map_lookup_elem(&pid_mount_ns_map, &pmns);
    if (!is_valid) return 0;
    
    increment_enter_count_ns(pidns, mntns);
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 arg1 = ctx->args[0];
    __u64 arg2 = ctx->args[1];
    __u64 arg3 = ctx->args[2];
    
    __u32 hdr = 0;
    __u32 idx = 0;
    
    struct audit_b *b = init_event(SOCKET_EN, &idx, &hdr, pidns, mntns);

    if (!b) return 0;
    
    __u32 original_size = calculate_original_size(__NR_socket, pid, arg1, arg2, arg3, 3);
    __u32 eaudit_size = calculate_eaudit_size(pid, arg1, arg2, arg3, 3);
    
    if (is_huffman_enabled()) {
        struct arg_key_3 arg_key = {
            .arg1 = arg1,
            .arg2 = arg2,
            .arg3 = arg3,
        };
        struct compressed_data *comp_data = bpf_map_lookup_elem(&huffman_rules_3, &arg_key);
        
        if (comp_data) {
            add_huffman_data(b, &idx, hdr, comp_data);
            
            __u32 pid_size = (pid > 0xFFFF) ? 3 : 2;
            __u32 huffman_event_size = 1 + 3 + 1 + pid_size + comp_data->length + 1;
            int saved_bytes = (int)eaudit_size - (int)huffman_event_size;
            
            update_huffman_stats_ns(pidns, mntns, 1, saved_bytes,
                                   original_size, eaudit_size, huffman_event_size);
        } else {
            add_args_3(b, &idx, hdr, arg1, arg2, arg3);
            update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
        }
    } else {
        add_args_3(b, &idx, hdr, arg1, arg2, arg3);
        update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
    }
    
    finish_event(b, idx, pidns, mntns);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept")
int trace_accept_enter(struct trace_event_raw_sys_enter *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;

    __u32 pidns = getPidInum(task);
    __u32 mntns = getMntInum(task);
    struct ns pmns = {.pidns = pidns, .mntns = mntns};
    
    __u64 *is_valid = bpf_map_lookup_elem(&pid_mount_ns_map, &pmns);
    if (!is_valid) return 0;
    
    increment_enter_count_ns(pidns, mntns);
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 arg1 = ctx->args[0];
    __u64 arg2 = ctx->args[1];
    __u64 arg3 = ctx->args[2];
    
    __u32 hdr = 0;
    __u32 idx = 0;
    
    struct audit_b *b = init_event(ACCEPT_EN, &idx, &hdr, pidns, mntns);

    if (!b) return 0;
    
    __u32 original_size = calculate_original_size(__NR_accept, pid, arg1, arg2, arg3, 3);
    __u32 eaudit_size = calculate_eaudit_size(pid, arg1, arg2, arg3, 3);
    
    if (is_huffman_enabled()) {
        struct arg_key_3 arg_key = {
            .arg1 = arg1,
            .arg2 = arg2,
            .arg3 = arg3,
        };
        struct compressed_data *comp_data = bpf_map_lookup_elem(&huffman_rules_3, &arg_key);
        
        if (comp_data) {
            add_huffman_data(b, &idx, hdr, comp_data);
            
            __u32 pid_size = (pid > 0xFFFF) ? 3 : 2;
            __u32 huffman_event_size = 1 + 3 + 1 + pid_size + comp_data->length + 1;
            int saved_bytes = (int)eaudit_size - (int)huffman_event_size;
            
            update_huffman_stats_ns(pidns, mntns, 1, saved_bytes,
                                   original_size, eaudit_size, huffman_event_size);
        } else {
            add_args_3(b, &idx, hdr, arg1, arg2, arg3);
            update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
        }
    } else {
        add_args_3(b, &idx, hdr, arg1, arg2, arg3);
        update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
    }
    
    finish_event(b, idx, pidns, mntns);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_bind")
int trace_bind_enter(struct trace_event_raw_sys_enter *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;

    __u32 pidns = getPidInum(task);
    __u32 mntns = getMntInum(task);
    struct ns pmns = {.pidns = pidns, .mntns = mntns};
    
    __u64 *is_valid = bpf_map_lookup_elem(&pid_mount_ns_map, &pmns);
    if (!is_valid) return 0;
    
    increment_enter_count_ns(pidns, mntns);
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 arg1 = ctx->args[0];
    __u64 arg2 = ctx->args[1];
    __u64 arg3 = ctx->args[2];
    
    __u32 hdr = 0;
    __u32 idx = 0;
    
    struct audit_b *b = init_event(BIND_EN, &idx, &hdr, pidns, mntns);

    if (!b) return 0;
    
    __u32 original_size = calculate_original_size(__NR_bind, pid, arg1, arg2, arg3, 3);
    __u32 eaudit_size = calculate_eaudit_size(pid, arg1, arg2, arg3, 3);
    
    if (is_huffman_enabled()) {
        struct arg_key_3 arg_key = {
            .arg1 = arg1,
            .arg2 = arg2,
            .arg3 = arg3,
        };
        struct compressed_data *comp_data = bpf_map_lookup_elem(&huffman_rules_3, &arg_key);
        
        if (comp_data) {
            add_huffman_data(b, &idx, hdr, comp_data);
            
            __u32 pid_size = (pid > 0xFFFF) ? 3 : 2;
            __u32 huffman_event_size = 1 + 3 + 1 + pid_size + comp_data->length + 1;
            int saved_bytes = (int)eaudit_size - (int)huffman_event_size;
            
            update_huffman_stats_ns(pidns, mntns, 1, saved_bytes,
                                   original_size, eaudit_size, huffman_event_size);
        } else {
            add_args_3(b, &idx, hdr, arg1, arg2, arg3);
            update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
        }
    } else {
        add_args_3(b, &idx, hdr, arg1, arg2, arg3);
        update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
    }
    
    finish_event(b, idx, pidns, mntns);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect_enter(struct trace_event_raw_sys_enter *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;

    __u32 pidns = getPidInum(task);
    __u32 mntns = getMntInum(task);
    struct ns pmns = {.pidns = pidns, .mntns = mntns};
    
    __u64 *is_valid = bpf_map_lookup_elem(&pid_mount_ns_map, &pmns);
    if (!is_valid) return 0;
    
    increment_enter_count_ns(pidns, mntns);
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 arg1 = ctx->args[0];
    __u64 arg2 = ctx->args[1];
    __u64 arg3 = ctx->args[2];
    
    __u32 hdr = 0;
    __u32 idx = 0;
    
    struct audit_b *b = init_event(CONNECT_EN, &idx, &hdr, pidns, mntns);

    if (!b) return 0;
    
    __u32 original_size = calculate_original_size(__NR_connect, pid, arg1, arg2, arg3, 3);
    __u32 eaudit_size = calculate_eaudit_size(pid, arg1, arg2, arg3, 3);
    
    if (is_huffman_enabled()) {
        struct arg_key_3 arg_key = {
            .arg1 = arg1,
            .arg2 = arg2,
            .arg3 = arg3,
        };
        struct compressed_data *comp_data = bpf_map_lookup_elem(&huffman_rules_3, &arg_key);
        
        if (comp_data) {
            add_huffman_data(b, &idx, hdr, comp_data);
            
            __u32 pid_size = (pid > 0xFFFF) ? 3 : 2;
            __u32 huffman_event_size = 1 + 3 + 1 + pid_size + comp_data->length + 1;
            int saved_bytes = (int)eaudit_size - (int)huffman_event_size;
            
            update_huffman_stats_ns(pidns, mntns, 1, saved_bytes,
                                   original_size, eaudit_size, huffman_event_size);
        } else {
            add_args_3(b, &idx, hdr, arg1, arg2, arg3);
            update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
        }
    } else {
        add_args_3(b, &idx, hdr, arg1, arg2, arg3);
        update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
    }
    
    finish_event(b, idx, pidns, mntns);
    return 0;
}

// =============================================================================
// LISTEN - 2  ( )
// =============================================================================

SEC("tracepoint/syscalls/sys_enter_listen")
int trace_listen_enter(struct trace_event_raw_sys_enter *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;

    __u32 pidns = getPidInum(task);
    __u32 mntns = getMntInum(task);
    struct ns pmns = {.pidns = pidns, .mntns = mntns};
    
    __u64 *is_valid = bpf_map_lookup_elem(&pid_mount_ns_map, &pmns);
    if (!is_valid) return 0;
    
    increment_enter_count_ns(pidns, mntns);
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 arg1 = ctx->args[0];
    __u64 arg2 = ctx->args[1];
    
    __u32 hdr = 0;
    __u32 idx = 0;
    
    struct audit_b *b = init_event(LISTEN_EN, &idx, &hdr, pidns, mntns);

    if (!b) return 0;
    
    __u32 original_size = calculate_original_size(__NR_listen, pid, arg1, arg2, 0, 2);
    __u32 eaudit_size = calculate_eaudit_size(pid, arg1, arg2, 0, 2);
    
    if (is_huffman_enabled()) {
        struct arg_key_2 arg_key = {
            .arg1 = arg1,
            .arg2 = arg2,
        };
        struct compressed_data *comp_data = bpf_map_lookup_elem(&huffman_rules_2, &arg_key);
        
        if (comp_data) {
            add_huffman_data(b, &idx, hdr, comp_data);
            
            __u32 pid_size = (pid > 0xFFFF) ? 3 : 2;
            __u32 huffman_event_size = 1 + 3 + 1 + pid_size + comp_data->length + 1;
            int saved_bytes = (int)eaudit_size - (int)huffman_event_size;
            
            update_huffman_stats_ns(pidns, mntns, 1, saved_bytes,
                                   original_size, eaudit_size, huffman_event_size);
        } else {
            add_args_2(b, &idx, hdr, arg1, arg2);
            update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
        }
    } else {
        add_args_2(b, &idx, hdr, arg1, arg2);
        update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
    }
    
    finish_event(b, idx, pidns, mntns);
    return 0;
}

// =============================================================================
// RECVFROM - 3  ( )
// =============================================================================

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_recvfrom_enter(struct trace_event_raw_sys_enter *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;

    __u32 pidns = getPidInum(task);
    __u32 mntns = getMntInum(task);
    struct ns pmns = {.pidns = pidns, .mntns = mntns};
    
    __u64 *is_valid = bpf_map_lookup_elem(&pid_mount_ns_map, &pmns);
    if (!is_valid) return 0;
    
    increment_enter_count_ns(pidns, mntns);
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 arg1 = ctx->args[0];
    __u64 arg2 = ctx->args[1];
    __u64 arg3 = ctx->args[2];
    
    __u32 hdr = 0;
    __u32 idx = 0;
    
    struct audit_b *b = init_event(RECVFROM_EN, &idx, &hdr, pidns, mntns);

    if (!b) return 0;
    
    __u32 original_size = calculate_original_size(__NR_recvfrom, pid, arg1, arg2, arg3, 3);
    __u32 eaudit_size = calculate_eaudit_size(pid, arg1, arg2, arg3, 3);
    
    if (is_huffman_enabled()) {
        struct arg_key_3 arg_key = {
            .arg1 = arg1,
            .arg2 = arg2,
            .arg3 = arg3,
        };
        struct compressed_data *comp_data = bpf_map_lookup_elem(&huffman_rules_3, &arg_key);
        
        if (comp_data) {
            add_huffman_data(b, &idx, hdr, comp_data);
            
            __u32 pid_size = (pid > 0xFFFF) ? 3 : 2;
            __u32 huffman_event_size = 1 + 3 + 1 + pid_size + comp_data->length + 1;
            int saved_bytes = (int)eaudit_size - (int)huffman_event_size;
            
            update_huffman_stats_ns(pidns, mntns, 1, saved_bytes,
                                   original_size, eaudit_size, huffman_event_size);
        } else {
            add_args_3(b, &idx, hdr, arg1, arg2, arg3);
            update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
        }
    } else {
        add_args_3(b, &idx, hdr, arg1, arg2, arg3);
        update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
    }
    
    finish_event(b, idx, pidns, mntns);
    return 0;
}

// =============================================================================
// ACCEPT4 - 3  ( )
// =============================================================================

SEC("tracepoint/syscalls/sys_enter_accept4")
int trace_accept4_enter(struct trace_event_raw_sys_enter *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;

    __u32 pidns = getPidInum(task);
    __u32 mntns = getMntInum(task);
    struct ns pmns = {.pidns = pidns, .mntns = mntns};
    
    __u64 *is_valid = bpf_map_lookup_elem(&pid_mount_ns_map, &pmns);
    if (!is_valid) return 0;
    
    increment_enter_count_ns(pidns, mntns);
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 arg1 = ctx->args[0];
    __u64 arg2 = ctx->args[1];
    __u64 arg3 = ctx->args[2];
    
    __u32 hdr = 0;
    __u32 idx = 0;
    
    struct audit_b *b = init_event(ACCEPT4_EN, &idx, &hdr, pidns, mntns);

    if (!b) return 0;
    
    __u32 original_size = calculate_original_size(__NR_accept4, pid, arg1, arg2, arg3, 3);
    __u32 eaudit_size = calculate_eaudit_size(pid, arg1, arg2, arg3, 3);
    
    if (is_huffman_enabled()) {
        struct arg_key_3 arg_key = {
            .arg1 = arg1,
            .arg2 = arg2,
            .arg3 = arg3,
        };
        struct compressed_data *comp_data = bpf_map_lookup_elem(&huffman_rules_3, &arg_key);
        
        if (comp_data) {
            add_huffman_data(b, &idx, hdr, comp_data);
            
            __u32 pid_size = (pid > 0xFFFF) ? 3 : 2;
            __u32 huffman_event_size = 1 + 3 + 1 + pid_size + comp_data->length + 1;
            int saved_bytes = (int)eaudit_size - (int)huffman_event_size;
            
            update_huffman_stats_ns(pidns, mntns, 1, saved_bytes,
                                   original_size, eaudit_size, huffman_event_size);
        } else {
            add_args_3(b, &idx, hdr, arg1, arg2, arg3);
            update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
        }
    } else {
        add_args_3(b, &idx, hdr, arg1, arg2, arg3);
        update_huffman_stats_ns(pidns, mntns, 0, 0, original_size, eaudit_size, eaudit_size);
    }
    
    finish_event(b, idx, pidns, mntns);
    return 0;
}

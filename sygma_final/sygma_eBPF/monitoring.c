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

struct execve_path_key {
    __u32 mntns;
    __u32 pidns;
    __u32 phase;
};

struct execve_path_value {
    __u32 count;           
    char paths[16][16];   
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

enum lsm_hook_type {
    LSM_FILE_PERMISSION = 1,
    LSM_INODE_GETATTR = 2,
    LSM_SOCKET_SENDMSG = 3,
    LSM_SOCKET_RECVMSG = 4,
    LSM_FILE_ALLOC = 5,
    LSM_MMAP_FILE = 6,         
    LSM_SOCKET_SETSOCKOPT = 7, 
    LSM_SOCKET_ACCEPT = 8,      
};

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
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocked_syscalls_map SEC(".maps");

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
    __type(key, struct execve_path_key);
    __type(value, struct execve_path_value);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} execve_path_map SEC(".maps");

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

static __always_inline int is_path_blocked(const u8 *path, 
                                           const struct execve_path_value *blocked_paths) {
    if (!blocked_paths || blocked_paths->count == 0) {
        return 0;
    }
    
    #pragma unroll
    for (__u32 i = 0; i < 16; i++) {
        if (i >= blocked_paths->count) continue;
        
        int match = 1;
        
        if (path[0] != blocked_paths->paths[i][0]) continue;
        if (path[1] != blocked_paths->paths[i][1]) continue;
        if (path[2] != blocked_paths->paths[i][2]) continue;
        if (path[3] != blocked_paths->paths[i][3]) continue;
        if (path[4] != blocked_paths->paths[i][4]) continue;
        if (path[5] != blocked_paths->paths[i][5]) continue;
        if (path[6] != blocked_paths->paths[i][6]) continue;
        if (path[7] != blocked_paths->paths[i][7]) continue;
        if (path[8] != blocked_paths->paths[i][8]) continue;
        if (path[9] != blocked_paths->paths[i][9]) continue;
        if (path[10] != blocked_paths->paths[i][10]) continue;
        if (path[11] != blocked_paths->paths[i][11]) continue;
        if (path[12] != blocked_paths->paths[i][12]) continue;
        if (path[13] != blocked_paths->paths[i][13]) continue;
        if (path[14] != blocked_paths->paths[i][14]) continue;
        if (path[15] != blocked_paths->paths[i][15]) continue;
        
        return 1; 
    }
    
    return 0;
}

static __always_inline void extract_binary_name(const u8 *path, u8 *binary_name) {
    __builtin_memset(binary_name, 0, 16);
    
    int last_slash = -1;
    
    if (path[0] == '/') last_slash = 0;
    if (path[1] == '/') last_slash = 1;
    if (path[2] == '/') last_slash = 2;
    if (path[3] == '/') last_slash = 3;
    if (path[4] == '/') last_slash = 4;
    if (path[5] == '/') last_slash = 5;
    if (path[6] == '/') last_slash = 6;
    if (path[7] == '/') last_slash = 7;
    if (path[8] == '/') last_slash = 8;
    if (path[9] == '/') last_slash = 9;
    if (path[10] == '/') last_slash = 10;
    if (path[11] == '/') last_slash = 11;
    if (path[12] == '/') last_slash = 12;
    if (path[13] == '/') last_slash = 13;
    if (path[14] == '/') last_slash = 14;
    
    if (last_slash >= 0 && last_slash < 15) {
        int src = last_slash + 1;
        #pragma unroll
        for (int i = 0; i < 15; i++) {
            if (src + i < 16) {
                binary_name[i] = path[src + i];
            }
        }
    } else {
        #pragma unroll
        for (int i = 0; i < 16; i++) {
            binary_name[i] = path[i];
        }
    }
}

static __always_inline int handle_execve_transition(struct pid_mount_ns *ns, __u32 phase, 
                                                      struct pt_regs *ctx, __u32 tid) {
    struct execve_path_key key = {
        .mntns = ns->mountns,
        .pidns = ns->pidns,
        .phase = phase,
    };
    
    u32 zero = 0;
    struct pt_regs *user_regs = bpf_map_lookup_elem(&percpu_regs, &zero);
    if (!user_regs) return 0;

    struct task_struct *task = (void *)bpf_get_current_task_btf();
    void *stack_base = BPF_CORE_READ(task, stack);
    if (!stack_base) return 0;
    
    unsigned long stack_top = (unsigned long)stack_base + 0x4000;
    void *regs_ptr = (void *)(stack_top - sizeof(struct pt_regs));
    
    if (bpf_probe_read_kernel(user_regs, sizeof(*user_regs), regs_ptr) != 0) {
        return 0;
    }
    
    const char __user *path_ptr = (const char __user *)user_regs->di;
    
    u8 path[16];
    __builtin_memset(path, 0, sizeof(path));
    
    if (bpf_probe_read_user_str(path, sizeof(path), path_ptr) <= 0) {
        return 0;
    }
    
    struct execve_path_value *blocked_paths = bpf_map_lookup_elem(&execve_path_map, &key);
    if (is_path_blocked(path, blocked_paths)) {
        return -1;
    }
        
    return 0;
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
    if (bit_index == 0xFFFFFFFF || bit_index >= 360) return 0;
    
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

static __always_inline int record_transition_lsm(
    struct pid_mount_ns *ns,
    __u32 tid,
    __u32 syscall_nr,
    __u32 phase,
    __u32 prev_syscall)
{
    struct collection_graph_key graph_key = {
        .mntns = ns->mountns,
        .pidns = ns->pidns,
        .prev_syscall = prev_syscall,
        .phase = phase,
    };
    
    struct collection_graph_value *graph_value = bpf_map_lookup_elem(&collection_graph_map, &graph_key);
    
    if (!graph_value) {
        struct collection_graph_value new_value = {};
        __builtin_memset(&new_value, 0, sizeof(new_value));
        
        if (set_syscall_bit(&new_value, syscall_nr) == 0) {
            bpf_map_update_elem(&collection_graph_map, &graph_key, &new_value, BPF_ANY);
        }
    } else {
        if (set_syscall_bit(graph_value, syscall_nr) == 0) {
            bpf_map_update_elem(&collection_graph_map, &graph_key, graph_value, BPF_EXIST);
        }
    }
    
    return 0;
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
        
        // 1. : "   (prev) -> 15"  ?
        struct syscall_graph_key graph_key;
        graph_key.mntns = ns.mountns;
        graph_key.pidns = ns.pidns;
        graph_key.from_syscall = ps->prev_syscall; //   
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
            history_key.from_syscall = ps->prev_syscall;
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

            ps->prev_syscall = ps->saved_prev_syscall; 
            ps->in_signal_handler = 0; //   
            bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
            
            // bpf_send_signal(9); //   
            return 0; 
        }

        ps->prev_syscall = ps->saved_prev_syscall;
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

    // execve argument 
    if (ps->current_syscall == __NR_execve) {
        int result = handle_execve_transition(&ns, phase, ctx, tid);
        if (result < 0) {
            return 0;
        }
    }

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
        
        if (ps->current_syscall == __NR_execve) {
            u32 zero = 0;
            struct pt_regs *user_regs = bpf_map_lookup_elem(&percpu_regs, &zero);
            if (!user_regs) return 0;

            struct task_struct *task = (void *)bpf_get_current_task_btf();
            void *stack_base = BPF_CORE_READ(task, stack);
            if (!stack_base) return 0;
            
            unsigned long stack_top = (unsigned long)stack_base + 0x4000;
            void *regs_ptr = (void *)(stack_top - sizeof(struct pt_regs));
            
            if (bpf_probe_read_kernel(user_regs, sizeof(*user_regs), regs_ptr) != 0) {
                return 0;
            }
            
            // rdi =    (execve )
            const char __user *path_ptr = (const char __user *)user_regs->di;
            
            char path[16];
            __builtin_memset(path, 0, sizeof(path));
            
            if (bpf_probe_read_user_str(path, sizeof(path), path_ptr) <= 0) {
                return 0;
            }
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
        }
        ps->prev_syscall = ps->current_syscall;
        bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
        // bpf_send_signal(9);
        return 0;
    }
    
    __u32 bit_index = syscall_to_bit_index(ps->current_syscall);
    if (bit_index == 0xFFFFFFFF || bit_index >= 360) return 0;
    
    __u32 byte_pos = bit_index >> 3;
    __u32 bit_offset = bit_index & 7;
    
    if (byte_pos >= 45) return 0;
    
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

    // bpf_send_signal(9);

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

	if (current_syscall == __NR_execve) {
		int result = handle_execve_transition(&ns, phase, ctx, tid);
		if (result < 0) {
			return 0;
		}
	}

    if (current_syscall == __NR_sigreturn) {
        // 1. : "    -> 15"   
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
            //   
            if (set_syscall_bit(graph_value, 15) == 0) {
                bpf_map_update_elem(&collection_graph_map, &graph_key, graph_value, BPF_EXIST);
            }
        }

        // 2. :    
        ps->prev_syscall = ps->saved_prev_syscall;
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
    return 0;
}

// =============================================================================
// Kprobe: sys_read (syscall 0) - LSM: file_permission
// =============================================================================

SEC("kprobe/__x64_sys_read")
int kprobe_sys_read(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    if (!task) return 0;
    
    struct pid_mount_ns ns;
    ns.pidns = getPidInum(task);
    ns.mountns = getMntInum(task);
    
    // Collection mode 
    __u32 *collection_mode = bpf_map_lookup_elem(&collection_mode_map, &ns);
    if (collection_mode && *collection_mode == 1) {
        struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
        if (!ps) return 0;
        
        __u32 phase = get_current_phase(task);
        record_transition_lsm(&ns, tid, 0, phase, ps->prev_syscall);
        
        ps->prev_syscall = 0;
        bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
        return 0;
    }

    __u64 *ns_map_value = bpf_map_lookup_elem(&pid_mount_ns_map, &ns);
    if (!ns_map_value) return 0;
    if (*ns_map_value == 1) {
        __u64 time = bpf_ktime_get_boot_ns();
        bpf_map_update_elem(&pid_mount_ns_map, &ns, &time, BPF_ANY);
    }
    
    // Enforcement mode
    struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
    if (!ps) return 0;
    
    __u32 phase = get_current_phase(task);
    increment_trigger_counter(TRIGGER_COUNTER_LSM);
    int result = verify_transition_lsm(&ns, tid, 0, phase, ps->prev_syscall, LSM_FILE_PERMISSION);
    
    //  prev_syscall  ( LSM )
    ps->prev_syscall = 0;
    bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
    
    return 0;
}

// =============================================================================
// Kprobe: sys_write (syscall 1) - LSM: file_permission
// =============================================================================

SEC("kprobe/__x64_sys_write")
int kprobe_sys_write(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    if (!task) return 0;
    
    struct pid_mount_ns ns;
    ns.pidns = getPidInum(task);
    ns.mountns = getMntInum(task);
    
    __u32 *collection_mode = bpf_map_lookup_elem(&collection_mode_map, &ns);
    if (collection_mode && *collection_mode == 1) {
        struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
        if (!ps) return 0;
        
        __u32 phase = get_current_phase(task);
        record_transition_lsm(&ns, tid, 1, phase, ps->prev_syscall);
        
        ps->prev_syscall = 1;
        bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
        return 0;
    }

    __u64 *ns_map_value = bpf_map_lookup_elem(&pid_mount_ns_map, &ns);
    if (!ns_map_value) return 0;
    if (*ns_map_value == 1) {
        __u64 time = bpf_ktime_get_boot_ns();
        bpf_map_update_elem(&pid_mount_ns_map, &ns, &time, BPF_ANY);
    }
    
    struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
    if (!ps) return 0;
    
    __u32 phase = get_current_phase(task);
    increment_trigger_counter(TRIGGER_COUNTER_LSM);
    verify_transition_lsm(&ns, tid, 1, phase, ps->prev_syscall, LSM_FILE_PERMISSION);
    
    ps->prev_syscall = 1;
    bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
    
    return 0;
}

// =============================================================================
// Kprobe: sys_newfstat (syscall 5) - LSM: security_inode_getattr
// =============================================================================

SEC("kprobe/__x64_sys_newfstat")
int kprobe_sys_newfstat(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    if (!task) return 0;
    
    struct pid_mount_ns ns;
    ns.pidns = getPidInum(task);
    ns.mountns = getMntInum(task);
    
    __u32 *collection_mode = bpf_map_lookup_elem(&collection_mode_map, &ns);
    if (collection_mode && *collection_mode == 1) {
        struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
        if (!ps) return 0;
        
        __u32 phase = get_current_phase(task);
        record_transition_lsm(&ns, tid, 5, phase, ps->prev_syscall);
        
        ps->prev_syscall = 5;
        bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
        return 0;
    }

    __u64 *ns_map_value = bpf_map_lookup_elem(&pid_mount_ns_map, &ns);
    if (!ns_map_value) return 0;
    if (*ns_map_value == 1) {
        __u64 time = bpf_ktime_get_boot_ns();
        bpf_map_update_elem(&pid_mount_ns_map, &ns, &time, BPF_ANY);
    }
    
    struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
    if (!ps) return 0;
    
    __u32 phase = get_current_phase(task);
    increment_trigger_counter(TRIGGER_COUNTER_LSM);
    verify_transition_lsm(&ns, tid, 5, phase, ps->prev_syscall, LSM_INODE_GETATTR);
    
    ps->prev_syscall = 5;
    bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
    
    return 0;
}

// =============================================================================
// Note: syscall 18 (sched_yield) is SKIPPED - async, no enforcement
// =============================================================================

// =============================================================================
// Kprobe: sys_writev (syscall 20) - LSM: file_permission
// =============================================================================

SEC("kprobe/__x64_sys_writev")
int kprobe_sys_writev(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    if (!task) return 0;
    
    struct pid_mount_ns ns;
    ns.pidns = getPidInum(task);
    ns.mountns = getMntInum(task);
    
    __u32 *collection_mode = bpf_map_lookup_elem(&collection_mode_map, &ns);
    if (collection_mode && *collection_mode == 1) {
        struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
        if (!ps) return 0;
        
        __u32 phase = get_current_phase(task);
        record_transition_lsm(&ns, tid, 20, phase, ps->prev_syscall);
        
        ps->prev_syscall = 20;
        bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
        return 0;
    }

    __u64 *ns_map_value = bpf_map_lookup_elem(&pid_mount_ns_map, &ns);
    if (!ns_map_value) return 0;
    if (*ns_map_value == 1) {
        __u64 time = bpf_ktime_get_boot_ns();
        bpf_map_update_elem(&pid_mount_ns_map, &ns, &time, BPF_ANY);
    }
    
    struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
    if (!ps) return 0;
    
    __u32 phase = get_current_phase(task);
    increment_trigger_counter(TRIGGER_COUNTER_LSM);
    verify_transition_lsm(&ns, tid, 20, phase, ps->prev_syscall, LSM_FILE_PERMISSION);
    
    ps->prev_syscall = 20;
    bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
    
    return 0;
}

// =============================================================================
// Note: syscall 24 is SKIPPED - async, no enforcement
// =============================================================================

// =============================================================================
// Kprobe: sys_sendfile (syscall 40) - LSM: file_permission
// =============================================================================

SEC("kprobe/__x64_sys_sendfile64")
int kprobe_sys_sendfile(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    if (!task) return 0;
    
    struct pid_mount_ns ns;
    ns.pidns = getPidInum(task);
    ns.mountns = getMntInum(task);
    
    __u32 *collection_mode = bpf_map_lookup_elem(&collection_mode_map, &ns);
    if (collection_mode && *collection_mode == 1) {
        struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
        if (!ps) return 0;
        
        __u32 phase = get_current_phase(task);
        record_transition_lsm(&ns, tid, 40, phase, ps->prev_syscall);
        
        ps->prev_syscall = 40;
        bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
        return 0;
    }

    __u64 *ns_map_value = bpf_map_lookup_elem(&pid_mount_ns_map, &ns);
    if (!ns_map_value) return 0;
    if (*ns_map_value == 1) {
        __u64 time = bpf_ktime_get_boot_ns();
        bpf_map_update_elem(&pid_mount_ns_map, &ns, &time, BPF_ANY);
    }
    
    struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
    if (!ps) return 0;
    
    __u32 phase = get_current_phase(task);
    increment_trigger_counter(TRIGGER_COUNTER_LSM);
    verify_transition_lsm(&ns, tid, 40, phase, ps->prev_syscall, LSM_FILE_PERMISSION);
    
    ps->prev_syscall = 40;
    bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
    
    return 0;
}

// =============================================================================
// Kprobe: sys_sendto (syscall 44) - LSM: socket_sendmsg
// =============================================================================

SEC("kprobe/__x64_sys_sendto")
int kprobe_sys_sendto(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    if (!task) return 0;
    
    struct pid_mount_ns ns;
    ns.pidns = getPidInum(task);
    ns.mountns = getMntInum(task);
    
    __u32 *collection_mode = bpf_map_lookup_elem(&collection_mode_map, &ns);
    if (collection_mode && *collection_mode == 1) {
        struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
        if (!ps) return 0;
        
        __u32 phase = get_current_phase(task);
        record_transition_lsm(&ns, tid, 44, phase, ps->prev_syscall);
        
        ps->prev_syscall = 44;
        bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
        return 0;
    }

    __u64 *ns_map_value = bpf_map_lookup_elem(&pid_mount_ns_map, &ns);
    if (!ns_map_value) return 0;
    if (*ns_map_value == 1) {
        __u64 time = bpf_ktime_get_boot_ns();
        bpf_map_update_elem(&pid_mount_ns_map, &ns, &time, BPF_ANY);
    }
    
    struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
    if (!ps) return 0;
    
    __u32 phase = get_current_phase(task);
    increment_trigger_counter(TRIGGER_COUNTER_LSM);
    verify_transition_lsm(&ns, tid, 44, phase, ps->prev_syscall, LSM_SOCKET_SENDMSG);
    
    ps->prev_syscall = 44;
    bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
    
    return 0;
}

// =============================================================================
// Kprobe: sys_recvfrom (syscall 45) - LSM: socket_recvmsg
// =============================================================================

SEC("kprobe/__x64_sys_recvfrom")
int kprobe_sys_recvfrom(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    if (!task) return 0;
    
    struct pid_mount_ns ns;
    ns.pidns = getPidInum(task);
    ns.mountns = getMntInum(task);
    
    __u32 *collection_mode = bpf_map_lookup_elem(&collection_mode_map, &ns);
    if (collection_mode && *collection_mode == 1) {
        struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
        if (!ps) return 0;
        
        __u32 phase = get_current_phase(task);
        record_transition_lsm(&ns, tid, 45, phase, ps->prev_syscall);
        
        ps->prev_syscall = 45;
        bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
        return 0;
    }

    __u64 *ns_map_value = bpf_map_lookup_elem(&pid_mount_ns_map, &ns);
    if (!ns_map_value) return 0;
    if (*ns_map_value == 1) {
        __u64 time = bpf_ktime_get_boot_ns();
        bpf_map_update_elem(&pid_mount_ns_map, &ns, &time, BPF_ANY);
    }
    
    struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
    if (!ps) return 0;
    
    __u32 phase = get_current_phase(task);
    increment_trigger_counter(TRIGGER_COUNTER_LSM);
    verify_transition_lsm(&ns, tid, 45, phase, ps->prev_syscall, LSM_SOCKET_RECVMSG);
    
    ps->prev_syscall = 45;
    bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
    
    return 0;
}

// =============================================================================
// Kprobe: sys_sendmsg (syscall 46) - LSM: security_socket_sendmsg
// =============================================================================

SEC("kprobe/__x64_sys_sendmsg")
int kprobe_sys_sendmsg(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    if (!task) return 0;
    
    struct pid_mount_ns ns;
    ns.pidns = getPidInum(task);
    ns.mountns = getMntInum(task);
    
    __u32 *collection_mode = bpf_map_lookup_elem(&collection_mode_map, &ns);
    if (collection_mode && *collection_mode == 1) {
        struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
        if (!ps) return 0;
        
        __u32 phase = get_current_phase(task);
        record_transition_lsm(&ns, tid, 46, phase, ps->prev_syscall);
        
        ps->prev_syscall = 46;
        bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
        return 0;
    }

    __u64 *ns_map_value = bpf_map_lookup_elem(&pid_mount_ns_map, &ns);
    if (!ns_map_value) return 0;
    if (*ns_map_value == 1) {
        __u64 time = bpf_ktime_get_boot_ns();
        bpf_map_update_elem(&pid_mount_ns_map, &ns, &time, BPF_ANY);
    }
    
    struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
    if (!ps) return 0;
    
    __u32 phase = get_current_phase(task);
    increment_trigger_counter(TRIGGER_COUNTER_LSM);
    verify_transition_lsm(&ns, tid, 46, phase, ps->prev_syscall, LSM_SOCKET_SENDMSG);
    
    ps->prev_syscall = 46;
    bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
    
    return 0;
}

// =============================================================================
// Kprobe: sys_recvmsg (syscall 47) - LSM: socket_recvmsg
// =============================================================================

SEC("kprobe/__x64_sys_recvmsg")
int kprobe_sys_recvmsg(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    if (!task) return 0;
    
    struct pid_mount_ns ns;
    ns.pidns = getPidInum(task);
    ns.mountns = getMntInum(task);
    
    __u32 *collection_mode = bpf_map_lookup_elem(&collection_mode_map, &ns);
    if (collection_mode && *collection_mode == 1) {
        struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
        if (!ps) return 0;
        
        __u32 phase = get_current_phase(task);
        record_transition_lsm(&ns, tid, 47, phase, ps->prev_syscall);
        
        ps->prev_syscall = 47;
        bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
        return 0;
    }

    __u64 *ns_map_value = bpf_map_lookup_elem(&pid_mount_ns_map, &ns);
    if (!ns_map_value) return 0;
    if (*ns_map_value == 1) {
        __u64 time = bpf_ktime_get_boot_ns();
        bpf_map_update_elem(&pid_mount_ns_map, &ns, &time, BPF_ANY);
    }
    
    struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
    if (!ps) return 0;
    
    __u32 phase = get_current_phase(task);
    increment_trigger_counter(TRIGGER_COUNTER_LSM);
    verify_transition_lsm(&ns, tid, 47, phase, ps->prev_syscall, LSM_SOCKET_RECVMSG);
    
    ps->prev_syscall = 47;
    bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
    
    return 0;
}

// =============================================================================
// Note: syscall 202 (futex) is SKIPPED - async, no enforcement
// =============================================================================

// =============================================================================
// Note: syscall 232 (epoll_wait) is SKIPPED - async, no enforcement
// =============================================================================

// =============================================================================
// Kprobe: sys_openat (syscall 257) - LSM: security_file_alloc
// =============================================================================

SEC("kprobe/__x64_sys_openat")
int kprobe_sys_openat(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    if (!task) return 0;
    
    struct pid_mount_ns ns;
    ns.pidns = getPidInum(task);
    ns.mountns = getMntInum(task);
    
    __u32 *collection_mode = bpf_map_lookup_elem(&collection_mode_map, &ns);
    if (collection_mode && *collection_mode == 1) {
        struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
        if (!ps) return 0;
        
        __u32 phase = get_current_phase(task);
        record_transition_lsm(&ns, tid, 257, phase, ps->prev_syscall);
        
        ps->prev_syscall = 257;
        bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
        return 0;
    }

    __u64 *ns_map_value = bpf_map_lookup_elem(&pid_mount_ns_map, &ns);
    if (!ns_map_value) return 0;
    if (*ns_map_value == 1) {
        __u64 time = bpf_ktime_get_boot_ns();
        bpf_map_update_elem(&pid_mount_ns_map, &ns, &time, BPF_ANY);
    }
    
    struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
    if (!ps) return 0;
    
    __u32 phase = get_current_phase(task);
    increment_trigger_counter(TRIGGER_COUNTER_LSM);
    verify_transition_lsm(&ns, tid, 257, phase, ps->prev_syscall, LSM_FILE_ALLOC);
    
    ps->prev_syscall = 257;
    bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
    
    return 0;
}

// =============================================================================
// Kprobe: sys_newfstatat (syscall 262) - LSM: security_inode_getattr
// =============================================================================

SEC("kprobe/__x64_sys_newfstatat")
int kprobe_sys_newfstatat(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    if (!task) return 0;
    
    struct pid_mount_ns ns;
    ns.pidns = getPidInum(task);
    ns.mountns = getMntInum(task);
    
    __u32 *collection_mode = bpf_map_lookup_elem(&collection_mode_map, &ns);
    if (collection_mode && *collection_mode == 1) {
        struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
        if (!ps) return 0;
        
        __u32 phase = get_current_phase(task);
        record_transition_lsm(&ns, tid, 262, phase, ps->prev_syscall);
        
        ps->prev_syscall = 262;
        bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
        return 0;
    }

    __u64 *ns_map_value = bpf_map_lookup_elem(&pid_mount_ns_map, &ns);
    if (!ns_map_value) return 0;
    if (*ns_map_value == 1) {
        __u64 time = bpf_ktime_get_boot_ns();
        bpf_map_update_elem(&pid_mount_ns_map, &ns, &time, BPF_ANY);
    }
    
    struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
    if (!ps) return 0;
    
    __u32 phase = get_current_phase(task);
    increment_trigger_counter(TRIGGER_COUNTER_LSM);
    verify_transition_lsm(&ns, tid, 262, phase, ps->prev_syscall, LSM_INODE_GETATTR);
    
    ps->prev_syscall = 262;
    bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
    
    return 0;
}

// =============================================================================
// Note: syscall 271 (ppoll) is SKIPPED - async, no enforcement
// =============================================================================

// =============================================================================
// Kprobe: sys_mmap (syscall 9) - LSM: security_mmap_file
// =============================================================================

SEC("kprobe/__x64_sys_mmap")
int kprobe_sys_mmap(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    if (!task) return 0;
    
    struct pid_mount_ns ns;
    ns.pidns = getPidInum(task);
    ns.mountns = getMntInum(task);
    
    __u32 *collection_mode = bpf_map_lookup_elem(&collection_mode_map, &ns);
    if (collection_mode && *collection_mode == 1) {
        struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
        if (!ps) return 0;
        
        __u32 phase = get_current_phase(task);
        record_transition_lsm(&ns, tid, 9, phase, ps->prev_syscall);
        
        ps->prev_syscall = 9;
        bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
        return 0;
    }

    __u64 *ns_map_value = bpf_map_lookup_elem(&pid_mount_ns_map, &ns);
    if (!ns_map_value) return 0;
    if (*ns_map_value == 1) {
        __u64 time = bpf_ktime_get_boot_ns();
        bpf_map_update_elem(&pid_mount_ns_map, &ns, &time, BPF_ANY);
    }
    
    struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
    if (!ps) return 0;
    
    __u32 phase = get_current_phase(task);
    increment_trigger_counter(TRIGGER_COUNTER_LSM);
    verify_transition_lsm(&ns, tid, 9, phase, ps->prev_syscall, LSM_MMAP_FILE);
    
    ps->prev_syscall = 9;
    bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
    
    return 0;
}

// =============================================================================
// Kprobe: sys_pread64 (syscall 17) - LSM: security_file_permission
// =============================================================================

SEC("kprobe/__x64_sys_pread64")
int kprobe_sys_pread64(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    if (!task) return 0;
    
    struct pid_mount_ns ns;
    ns.pidns = getPidInum(task);
    ns.mountns = getMntInum(task);
    
    __u32 *collection_mode = bpf_map_lookup_elem(&collection_mode_map, &ns);
    if (collection_mode && *collection_mode == 1) {
        struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
        if (!ps) return 0;
        
        __u32 phase = get_current_phase(task);
        record_transition_lsm(&ns, tid, 17, phase, ps->prev_syscall);
        
        ps->prev_syscall = 17;
        bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
        return 0;
    }

    __u64 *ns_map_value = bpf_map_lookup_elem(&pid_mount_ns_map, &ns);
    if (!ns_map_value) return 0;
    if (*ns_map_value == 1) {
        __u64 time = bpf_ktime_get_boot_ns();
        bpf_map_update_elem(&pid_mount_ns_map, &ns, &time, BPF_ANY);
    }
    
    struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
    if (!ps) return 0;
    
    __u32 phase = get_current_phase(task);
    increment_trigger_counter(TRIGGER_COUNTER_LSM);
    verify_transition_lsm(&ns, tid, 17, phase, ps->prev_syscall, LSM_FILE_PERMISSION);
    
    ps->prev_syscall = 17;
    bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
    
    return 0;
}

// =============================================================================
// Kprobe: sys_pwrite64 (syscall 18) - LSM: security_file_permission
// =============================================================================

SEC("kprobe/__x64_sys_pwrite64")
int kprobe_sys_pwrite64(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    if (!task) return 0;
    
    struct pid_mount_ns ns;
    ns.pidns = getPidInum(task);
    ns.mountns = getMntInum(task);
    
    __u32 *collection_mode = bpf_map_lookup_elem(&collection_mode_map, &ns);
    if (collection_mode && *collection_mode == 1) {
        struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
        if (!ps) return 0;
        
        __u32 phase = get_current_phase(task);
        record_transition_lsm(&ns, tid, 18, phase, ps->prev_syscall);
        
        ps->prev_syscall = 18;
        bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
        return 0;
    }

    __u64 *ns_map_value = bpf_map_lookup_elem(&pid_mount_ns_map, &ns);
    if (!ns_map_value) return 0;
    if (*ns_map_value == 1) {
        __u64 time = bpf_ktime_get_boot_ns();
        bpf_map_update_elem(&pid_mount_ns_map, &ns, &time, BPF_ANY);
    }
    
    struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
    if (!ps) return 0;
    
    __u32 phase = get_current_phase(task);
    increment_trigger_counter(TRIGGER_COUNTER_LSM);
    verify_transition_lsm(&ns, tid, 18, phase, ps->prev_syscall, LSM_FILE_PERMISSION);
    
    ps->prev_syscall = 18;
    bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
    
    return 0;
}

// =============================================================================
// Kprobe: sys_setsockopt (syscall 54) - LSM: security_socket_setsockopt
// =============================================================================

SEC("kprobe/__x64_sys_setsockopt")
int kprobe_sys_setsockopt(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    if (!task) return 0;
    
    struct pid_mount_ns ns;
    ns.pidns = getPidInum(task);
    ns.mountns = getMntInum(task);
    
    __u32 *collection_mode = bpf_map_lookup_elem(&collection_mode_map, &ns);
    if (collection_mode && *collection_mode == 1) {
        struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
        if (!ps) return 0;
        
        __u32 phase = get_current_phase(task);
        record_transition_lsm(&ns, tid, 54, phase, ps->prev_syscall);
        
        ps->prev_syscall = 54;
        bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
        return 0;
    }

    __u64 *ns_map_value = bpf_map_lookup_elem(&pid_mount_ns_map, &ns);
    if (!ns_map_value) return 0;
    if (*ns_map_value == 1) {
        __u64 time = bpf_ktime_get_boot_ns();
        bpf_map_update_elem(&pid_mount_ns_map, &ns, &time, BPF_ANY);
    }
    
    struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
    if (!ps) return 0;
    
    __u32 phase = get_current_phase(task);
    increment_trigger_counter(TRIGGER_COUNTER_LSM);
    verify_transition_lsm(&ns, tid, 54, phase, ps->prev_syscall, LSM_SOCKET_SETSOCKOPT);
    
    ps->prev_syscall = 54;
    bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
    
    return 0;
}

// =============================================================================
// Kprobe: sys_accept4 (syscall 288) - LSM: security_socket_accept
// =============================================================================

SEC("kprobe/__x64_sys_accept4")
int kprobe_sys_accept4(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    if (!task) return 0;
    
    struct pid_mount_ns ns;
    ns.pidns = getPidInum(task);
    ns.mountns = getMntInum(task);
    
    __u32 *collection_mode = bpf_map_lookup_elem(&collection_mode_map, &ns);
    if (collection_mode && *collection_mode == 1) {
        struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
        if (!ps) return 0;
        
        __u32 phase = get_current_phase(task);
        record_transition_lsm(&ns, tid, 288, phase, ps->prev_syscall);
        
        ps->prev_syscall = 288;
        bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
        return 0;
    }

    __u64 *ns_map_value = bpf_map_lookup_elem(&pid_mount_ns_map, &ns);
    if (!ns_map_value) return 0;
    if (*ns_map_value == 1) {
        __u64 time = bpf_ktime_get_boot_ns();
        bpf_map_update_elem(&pid_mount_ns_map, &ns, &time, BPF_ANY);
    }
    
    struct process_state *ps = bpf_map_lookup_elem(&process_state_map, &tid);
    if (!ps) return 0;
    
    __u32 phase = get_current_phase(task);
    increment_trigger_counter(TRIGGER_COUNTER_LSM);
    verify_transition_lsm(&ns, tid, 288, phase, ps->prev_syscall, LSM_SOCKET_ACCEPT);
    
    ps->prev_syscall = 288;
    bpf_map_update_elem(&process_state_map, &tid, ps, BPF_ANY);
    
    return 0;
}

// =============================================================================
// LSM Hooks
// =============================================================================

SEC("lsm/file_permission")
int BPF_PROG(lsm_file_permission, struct file *file, int mask) {
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    struct lsm_block_key key = {
        .tid = tid,
        .lsm_hook_type = LSM_FILE_PERMISSION,
    };
    
    __u32 *blocked_syscall = bpf_map_lookup_elem(&lsm_block_map, &key);
    if (blocked_syscall) {
        // Cleanup
        bpf_map_delete_elem(&lsm_block_map, &key);
        
        //  (0, 1, 20, 40  )
        // return -EPERM;
    }
    
    return 0;  // 
}

SEC("lsm/inode_getattr")
int BPF_PROG(lsm_inode_getattr, const struct path *path) {
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    struct lsm_block_key key = {
        .tid = tid,
        .lsm_hook_type = LSM_INODE_GETATTR,
    };
    
    __u32 *blocked_syscall = bpf_map_lookup_elem(&lsm_block_map, &key);
    if (blocked_syscall) {
        bpf_map_delete_elem(&lsm_block_map, &key);
        // return -EPERM;
    }
    
    return 0;
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(lsm_socket_sendmsg, struct socket *sock, struct msghdr *msg, int size) {
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    struct lsm_block_key key = {
        .tid = tid,
        .lsm_hook_type = LSM_SOCKET_SENDMSG,
    };
    
    __u32 *blocked_syscall = bpf_map_lookup_elem(&lsm_block_map, &key);
    if (blocked_syscall) {
        bpf_map_delete_elem(&lsm_block_map, &key);
        // return -EPERM;
    }
    
    return 0;
}

SEC("lsm/socket_recvmsg")
int BPF_PROG(lsm_socket_recvmsg, struct socket *sock, struct msghdr *msg, int size, int flags) {
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    struct lsm_block_key key = {
        .tid = tid,
        .lsm_hook_type = LSM_SOCKET_RECVMSG,
    };
    
    __u32 *blocked_syscall = bpf_map_lookup_elem(&lsm_block_map, &key);
    if (blocked_syscall) {
        bpf_map_delete_elem(&lsm_block_map, &key);
        // return -EPERM;
    }
    
    return 0;
}

SEC("lsm/file_alloc_security")
int BPF_PROG(lsm_file_alloc_security, struct file *file) {
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    struct lsm_block_key key = {
        .tid = tid,
        .lsm_hook_type = LSM_FILE_ALLOC,
    };
    
    __u32 *blocked_syscall = bpf_map_lookup_elem(&lsm_block_map, &key);
    if (blocked_syscall) {
        bpf_map_delete_elem(&lsm_block_map, &key);
        // return -EPERM;
    }
    
    return 0;
}

SEC("lsm/mmap_file")
int BPF_PROG(lsm_mmap_file, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags) {
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    struct lsm_block_key key = {
        .tid = tid,
        .lsm_hook_type = LSM_MMAP_FILE,
    };
    
    __u32 *blocked_syscall = bpf_map_lookup_elem(&lsm_block_map, &key);
    if (blocked_syscall) {
        bpf_map_delete_elem(&lsm_block_map, &key);
        // return -EPERM;
    }
    
    return 0;
}

SEC("lsm/socket_setsockopt")
int BPF_PROG(lsm_socket_setsockopt, struct socket *sock, int level, int optname) {
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    struct lsm_block_key key = {
        .tid = tid,
        .lsm_hook_type = LSM_SOCKET_SETSOCKOPT,
    };
    
    __u32 *blocked_syscall = bpf_map_lookup_elem(&lsm_block_map, &key);
    if (blocked_syscall) {
        bpf_map_delete_elem(&lsm_block_map, &key);
        // return -EPERM;
    }
    
    return 0;
}

SEC("lsm/socket_accept")
int BPF_PROG(lsm_socket_accept, struct socket *sock, struct socket *newsock) {
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    struct lsm_block_key key = {
        .tid = tid,
        .lsm_hook_type = LSM_SOCKET_ACCEPT,
    };
    
    __u32 *blocked_syscall = bpf_map_lookup_elem(&lsm_block_map, &key);
    if (blocked_syscall) {
        bpf_map_delete_elem(&lsm_block_map, &key);
        // return -EPERM;
    }
    
    return 0;
}

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

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define INIT_PROCESS -1

// Tail call  
enum {
    // PROG_STAGE1_FILTER = 0,
    PROG_STAGE2_CHECK = 0,
    PROG_STAGE3_VERIFY,
    PROG_MAX
};

//  
struct process_context {
    __u32 pid;
    __u32 syscall_nr;
    __u32 image_id;
    __u32 generation;
    __u32 pidns;
    __u32 mntns;
};

struct pid_mount_ns {
    __u32 mountns;
    __u32 pidns;
};

struct syscall_graph_key {
    __u32 image_id;
    __u32 from_syscall;
    __u32 generation;
};

struct syscall_graph_value {
    __u8 allowed_mask[45];
};

struct execution_value {
    __u8 comm[16];
    __u32 execution_time;
};

struct image_metadata_value {
    __u32 total_generations;
    __s32 loop_generation;
    __u32 entry_system_call;
};

// ===   (  ) ===

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, PROG_MAX);
} prog_array SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct process_context));
    __uint(max_entries, 1);
} percpu_context SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct syscall_graph_key);
    __type(value, struct syscall_graph_value);
    __uint(max_entries, 50000);
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
    __type(key, struct pid_mount_ns);
    __type(value, __u32);
    __uint(max_entries, 64);
} main_pid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct image_metadata_value);
    __uint(max_entries, 1000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} syscall_metadata_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1000);
} previous_syscall_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct pid_mount_ns);
    __type(value, __u32);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} containerID_PID_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1024);
} process_generation_map SEC(".maps");

// ===   () ===

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

// === STAGE 1:      ===
SEC("raw_tracepoint/sys_enter")
int stage1_filter(struct bpf_raw_tracepoint_args *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;
    
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 syscall_nr = ctx->args[1];
    __u32 cpu = bpf_get_smp_processor_id();
    
    // Namespace 
    __u32 pidns = getPidInum(task);
    __u32 mntns = getMntInum(task);
    struct pid_mount_ns ns = {.pidns = pidns, .mountns = mntns};
    
    //  
    __u32 *image_id = bpf_map_lookup_elem(&containerID_PID_map, &ns);
    if (!image_id) return 0;  //  
    
    //  
    struct process_context ctx_data = {
        .pid = pid,
        .syscall_nr = syscall_nr,
        .image_id = *image_id,
        .generation = 0,
        .pidns = pidns,
        .mntns = mntns
    };
    
    //  
    bpf_map_update_elem(&percpu_context, &cpu, &ctx_data, BPF_ANY);
    
    // STAGE2 
    bpf_tail_call(ctx, &prog_array, PROG_STAGE2_CHECK);
    return 0;
}

// === STAGE 2: Generation  ===
SEC("raw_tracepoint/sys_enter")
int stage2_check(struct bpf_raw_tracepoint_args *ctx) {
    __u32 cpu = bpf_get_smp_processor_id();
    struct process_context *ctx_data = bpf_map_lookup_elem(&percpu_context, &cpu);
    if (!ctx_data) return 0;
    
    struct pid_mount_ns ns = {
        .pidns = ctx_data->pidns,
        .mountns = ctx_data->mntns
    };
    
    // Execution  (  )
    struct execution_value *exec_value = bpf_map_lookup_elem(&execution_time_map, &ns);
    if (exec_value && exec_value->execution_time == 0) {
        __u8 comm[16];
        bpf_get_current_comm(comm, 16);
        bpf_printk("Stage2: Execution check binary: %s\n", comm);
        if (check_comm(comm, exec_value->comm)) {
            exec_value->execution_time = 1;
            bpf_map_update_elem(&execution_time_map, &ns, exec_value, BPF_ANY);
            bpf_map_update_elem(&main_pid_map, &ns, &ctx_data->pid, BPF_ANY);
        }
    }
    
    // Main PID 
    __u32 *main_pid = bpf_map_lookup_elem(&main_pid_map, &ns);
    if (!main_pid) return 0;
    
    // Generation  (  )
    if (ctx_data->pid == *main_pid) {
        ctx_data->generation = 1;
    } else {
        __u32 *cached_gen = bpf_map_lookup_elem(&process_generation_map, &ctx_data->pid);
        if (cached_gen && *cached_gen > 0) {
            ctx_data->generation = *cached_gen;
        } else {
            // Generation  ( 5 )
            struct task_struct *task = (struct task_struct *)bpf_get_current_task();
            struct task_struct *current_task = task;
            int generation = 2;
            
            #pragma unroll
            for (int i = 0; i < 4; i++) {  //  8 
                if (!current_task) break;
                
                current_task = BPF_CORE_READ(current_task, real_parent);
                if (!current_task) break;
                
                __u32 parent_pid = BPF_CORE_READ(current_task, pid);
                
                if (parent_pid <= 1) {
                    generation = -1;  // INIT_PROCESS
                    break;
                }
                
                if (parent_pid == *main_pid) {
                    break;  // main_pid 
                }
                
                generation++;
                if (generation > 10) {  //   
                    break;
                }
            }
            
            ctx_data->generation = generation;
            
            //  
            if (generation > 0 && generation <= 10) {
                bpf_map_update_elem(&process_generation_map, &ctx_data->pid, 
                                  &generation, BPF_ANY);
            }
        }
    }
    
    if (ctx_data->generation == -1) {
        return INIT_PROCESS;  // INIT  
    }
    
    //  
    bpf_map_update_elem(&percpu_context, &cpu, ctx_data, BPF_ANY);
    
    // STAGE3 
    bpf_tail_call(ctx, &prog_array, PROG_STAGE3_VERIFY);
    return 0;
}

// === STAGE 3:   ===
SEC("raw_tracepoint/sys_enter")
int stage3_verify(struct bpf_raw_tracepoint_args *ctx) {
    __u32 cpu = bpf_get_smp_processor_id();
    struct process_context *ctx_data = bpf_map_lookup_elem(&percpu_context, &cpu);
    if (!ctx_data) return 0;
    
    //  
    struct image_metadata_value *metadata = 
        bpf_map_lookup_elem(&syscall_metadata_map, &ctx_data->image_id);
    if (!metadata) return 0;
    
    //    
    __u32 *prev_syscall = bpf_map_lookup_elem(&previous_syscall_map, &ctx_data->pid);
    
    if (!prev_syscall) {
        //    
        bpf_printk("Stage3: prev_syscall is null, ctx_data->syscall_nr : %u, entry_system_call : %u", ctx_data->syscall_nr, metadata->entry_system_call);
        if (ctx_data->syscall_nr == metadata->entry_system_call) {
            bpf_map_update_elem(&previous_syscall_map, &ctx_data->pid, 
                              &ctx_data->syscall_nr, BPF_ANY);
            return 1;  // 
        }
        return 0;  // 
    }
    
    // bpf_printk("Stage3: Verifying syscall transition with prev");
    // Generation  ( )
    __u32 generation = ctx_data->generation - 1;
    __u32 effective_generation = generation;
    
    if (metadata->loop_generation >= 0 && generation > metadata->total_generations) {
        __u32 loop_start = (__u32)metadata->loop_generation;
        __u32 loop_size = metadata->total_generations - loop_start + 1;
        
        if (loop_size > 0) {
            __u32 excess = generation - loop_start;
            effective_generation = loop_start + (excess % loop_size);
        }
    }
    
    if (effective_generation > metadata->total_generations) {
        return 0;
    }
    
    //  
    struct syscall_graph_key graph_key = {
        .from_syscall = *prev_syscall,
        .generation = effective_generation,
        .image_id = ctx_data->image_id
    };
    
    struct syscall_graph_value *graph_value = 
        bpf_map_lookup_elem(&syscall_graph_map, &graph_key);
    if (!graph_value) return 0;
    
    //  
    __u32 bit_index = syscall_to_bit_index(ctx_data->syscall_nr);
    if (bit_index == 0xFFFFFFFF) return 0;
    
    //   360   (45 bytes * 8 bits)
    if (bit_index >= 360) return 0;
    
    __u32 byte_pos = bit_index / 8;
    __u32 bit_offset = bit_index % 8;
    
    // byte_pos 45   
    if (byte_pos >= 45) return 0;
    
    //    ()
    __u32 byte_index = 44 - byte_pos;
    
    //      
    if (byte_index > 44) return 0;
    
    __u8 byte_value;
    //      
    if (byte_index < 45) {
        byte_value = graph_value->allowed_mask[byte_index & 0x2C]; // & 0x3F  
    } else {
        return 0;
    }
    
    __u8 mask = 1 << (bit_offset & 7);  // bit_offset  
    
    if (byte_value & mask) {
        //   -    
        bpf_map_update_elem(&previous_syscall_map, &ctx_data->pid, 
                          &ctx_data->syscall_nr, BPF_ANY);
        bpf_printk("trasition allowed!");
        return 1;
    }
    bpf_printk("transition blocked!");
    return 0;  // 
}

// ===   ===
// SEC("raw_tracepoint/sys_enter")
// int rtp_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
//     bpf_tail_call(ctx, &prog_array, PROG_STAGE1_FILTER)
//     return 0;
// }

#define _GNU_SOURCE

#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <stddef.h>
#include <dirent.h>

#define MAX_PATH 2048
#define MAX_LOG_BUF 512
#define SYGMA_SECCOMP_ROUTING_ENV "SYGMA_SECCOMP_ROUTING"
#define SYGMA_SECCOMP_ROUTING_SELECTIVE "selective"
#define SYGMA_SECCOMP_ROUTING_ALL_TRACE "all-trace"

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#define BPF_STMT(code, k) { (unsigned short)(code), 0, 0, k }
#define BPF_JUMP(code, k, jt, jf) { (unsigned short)(code), jt, jf, k }

#define LSM_OBSERVED_SYSCALLS(X) \
    X(0, read) \
    X(1, write) \
    X(4, stat) \
    X(5, fstat) \
    X(6, lstat) \
    X(9, mmap) \
    X(16, ioctl) \
    X(17, pread64) \
    X(18, pwrite64) \
    X(22, pipe) \
    X(30, shmat) \
    X(40, sendfile) \
    X(41, socket) \
    X(42, connect) \
    X(43, accept) \
    X(44, sendto) \
    X(45, recvfrom) \
    X(46, sendmsg) \
    X(47, recvmsg) \
    X(48, shutdown) \
    X(49, bind) \
    X(50, listen) \
    X(51, getsockname) \
    X(52, getpeername) \
    X(53, socketpair) \
    X(54, setsockopt) \
    X(55, getsockopt) \
    X(59, execve) \
    X(65, semop) \
    X(69, msgsnd) \
    X(72, fcntl) \
    X(73, flock) \
    X(76, truncate) \
    X(77, ftruncate) \
    X(80, chdir) \
    X(81, fchdir) \
    X(82, rename) \
    X(83, mkdir) \
    X(84, rmdir) \
    X(86, link) \
    X(87, unlink) \
    X(88, symlink) \
    X(90, chmod) \
    X(91, fchmod) \
    X(92, chown) \
    X(93, fchown) \
    X(94, lchown) \
    X(103, syslog) \
    X(105, setuid) \
    X(106, setgid) \
    X(109, setpgid) \
    X(113, setreuid) \
    X(114, setregid) \
    X(116, setgroups) \
    X(117, setresuid) \
    X(119, setresgid) \
    X(126, capset) \
    X(133, mknod) \
    X(136, ustat) \
    X(137, statfs) \
    X(138, fstatfs) \
    X(142, sched_setparam) \
    X(143, sched_getparam) \
    X(144, sched_setscheduler) \
    X(145, sched_getscheduler) \
    X(148, sched_rr_get_interval) \
    X(153, vhangup) \
    X(155, pivot_root) \
    X(161, chroot) \
    X(163, acct) \
    X(164, settimeofday) \
    X(165, mount) \
    X(166, umount2) \
    X(167, swapon) \
    X(168, swapoff) \
    X(169, reboot) \
    X(170, sethostname) \
    X(171, setdomainname) \
    X(175, init_module) \
    X(176, delete_module) \
    X(179, quotactl) \
    X(188, setxattr) \
    X(189, lsetxattr) \
    X(190, fsetxattr) \
    X(191, getxattr) \
    X(192, lgetxattr) \
    X(193, fgetxattr) \
    X(194, listxattr) \
    X(195, llistxattr) \
    X(196, flistxattr) \
    X(197, removexattr) \
    X(198, lremovexattr) \
    X(199, fremovexattr) \
    X(203, sched_setaffinity) \
    X(204, sched_getaffinity) \
    X(213, epoll_create) \
    X(240, mq_open) \
    X(241, mq_unlink) \
    X(246, kexec_load) \
    X(253, inotify_init) \
    X(254, inotify_add_watch) \
    X(256, migrate_pages) \
    X(258, mkdirat) \
    X(259, mknodat) \
    X(260, fchownat) \
    X(262, newfstatat) \
    X(264, renameat) \
    X(265, linkat) \
    X(266, symlinkat) \
    X(268, fchmodat) \
    X(283, timerfd_create) \
    X(284, eventfd) \
    X(285, fallocate) \
    X(288, accept4) \
    X(290, eventfd2) \
    X(291, epoll_create1) \
    X(293, pipe2) \
    X(294, inotify_init1) \
     \
     \
    X(300, fanotify_init) \
    X(304, open_by_handle_at) \
    X(313, finit_module) \
    X(314, sched_setattr) \
    X(315, sched_getattr) \
    X(316, renameat2) \
    X(319, memfd_create) \
    X(320, kexec_file_load) \
    X(321, bpf) \
    X(322, execveat) \
    X(323, userfaultfd) \
    X(326, copy_file_range) \
    X(332, statx) \
    X(428, open_tree) \
    X(429, move_mount) \
    X(430, fsopen) \
    X(432, fsmount) \
    X(433, fspick) \
    X(434, pidfd_open) \
    X(438, pidfd_getfd) \
    X(440, process_madvise) \
    X(442, mount_setattr) \
    X(443, quotactl_fd)

#define DIRECT_OBSERVED_SYSCALLS(X) \
    X(56, clone) \
    X(57, fork) \
    X(58, vfork) \
    X(435, clone3)

#define ASYNC_BYPASS_SYSCALLS(X) \
    X(24, sched_yield) \
    X(202, futex) \
    X(232, epoll_wait) \
    X(271, ppoll)

#define COUNT_SYSCALL(nr, name) +1
enum {
    LSM_OBSERVED_SYSCALL_COUNT = 0 LSM_OBSERVED_SYSCALLS(COUNT_SYSCALL),
    DIRECT_OBSERVED_SYSCALL_COUNT = 0 DIRECT_OBSERVED_SYSCALLS(COUNT_SYSCALL),
    ASYNC_BYPASS_SYSCALL_COUNT = 0 ASYNC_BYPASS_SYSCALLS(COUNT_SYSCALL),
    PTRACE_BYPASS_SYSCALL_COUNT =
        LSM_OBSERVED_SYSCALL_COUNT +
        DIRECT_OBSERVED_SYSCALL_COUNT +
        ASYNC_BYPASS_SYSCALL_COUNT,
    SELECTIVE_SECCOMP_FILTER_INSTRUCTION_COUNT =
        2 + (PTRACE_BYPASS_SYSCALL_COUNT * 2),
    ALL_TRACE_SECCOMP_FILTER_INSTRUCTION_COUNT = 1,
};
#undef COUNT_SYSCALL

enum seccomp_routing_mode {
    SECCOMP_ROUTING_SELECTIVE,
    SECCOMP_ROUTING_ALL_TRACE,
};

_Static_assert(LSM_OBSERVED_SYSCALL_COUNT == 141, "dedicated observation route count changed");
_Static_assert(DIRECT_OBSERVED_SYSCALL_COUNT == 4, "direct observation route count changed");
_Static_assert(ASYNC_BYPASS_SYSCALL_COUNT == 4, "async syscall route count changed");
_Static_assert(SELECTIVE_SECCOMP_FILTER_INSTRUCTION_COUNT <= 4096,
               "selective seccomp filter is too large");
_Static_assert(ALL_TRACE_SECCOMP_FILTER_INSTRUCTION_COUNT == 1,
               "all-trace seccomp filter must remain a single instruction");

static char g_found_binary_path[MAX_PATH] = {0};

static int copy_path(char *destination, size_t capacity, const char *source) {
    size_t length = strnlen(source, capacity);

    if (length >= capacity) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(destination, source, length + 1);
    return 0;
}

static int real_binary_path(char *destination, size_t capacity,
                            const char *source) {
    static const char suffix[] = ".real";
    size_t length = strnlen(source, capacity);

    if (length >= capacity || sizeof(suffix) > capacity - length) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(destination, source, length);
    memcpy(destination + length, suffix, sizeof(suffix));
    return 0;
}

static void log_msg(const char *msg) {
    fprintf(stderr, "[sygma-wrapper] %s\n", msg);
    fflush(stderr);
}

static void log_msgf(const char *fmt, ...) {
    char buf[MAX_LOG_BUF];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    log_msg(buf);
}

static int parse_seccomp_routing(const char *value,
                                 enum seccomp_routing_mode *routing) {
    if (routing == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (value == NULL || value[0] == '\0' ||
        strcmp(value, SYGMA_SECCOMP_ROUTING_SELECTIVE) == 0) {
        *routing = SECCOMP_ROUTING_SELECTIVE;
        return 0;
    }
    if (strcmp(value, SYGMA_SECCOMP_ROUTING_ALL_TRACE) == 0) {
        *routing = SECCOMP_ROUTING_ALL_TRACE;
        return 0;
    }

    errno = EINVAL;
    return -1;
}

static int install_seccomp_filter(const char *routing_value) {
    enum seccomp_routing_mode routing;
    if (parse_seccomp_routing(routing_value, &routing) != 0) {
        log_msgf("ERROR: Unsupported %s value: %s",
                 SYGMA_SECCOMP_ROUTING_ENV,
                 routing_value != NULL ? routing_value : "(null)");
        return -1;
    }

    struct seccomp_data {
        int nr;
        __u32 arch;
        __u64 instruction_pointer;
        __u64 args[6];
    };

#define ALLOW_RULE(nr, name) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

    struct sock_filter selective_filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

        ASYNC_BYPASS_SYSCALLS(ALLOW_RULE)
        DIRECT_OBSERVED_SYSCALLS(ALLOW_RULE)
        LSM_OBSERVED_SYSCALLS(ALLOW_RULE)

        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
    };

    struct sock_filter all_trace_filter[] = {
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
    };

#undef ALLOW_RULE

    _Static_assert(
        sizeof(selective_filter) / sizeof(selective_filter[0]) ==
            SELECTIVE_SECCOMP_FILTER_INSTRUCTION_COUNT,
        "selective seccomp filter instruction count mismatch");
    _Static_assert(
        sizeof(all_trace_filter) / sizeof(all_trace_filter[0]) ==
            ALL_TRACE_SECCOMP_FILTER_INSTRUCTION_COUNT,
        "all-trace seccomp filter instruction count mismatch");

    struct sock_fprog prog = {0};
    if (routing == SECCOMP_ROUTING_ALL_TRACE) {
        prog.len = (unsigned short)(sizeof(all_trace_filter) /
                                    sizeof(all_trace_filter[0]));
        prog.filter = all_trace_filter;
        log_msg("🔒 Installing all-trace seccomp filter...");
        log_msg("   Every syscall: SECCOMP_RET_TRACE");
    } else {
        prog.len = (unsigned short)(sizeof(selective_filter) /
                                    sizeof(selective_filter[0]));
        prog.filter = selective_filter;
        log_msg("🔒 Installing selective seccomp filter...");
        log_msgf("   ALLOW: %d LSM-observed + %d direct-observed + %d asynchronous syscalls",
                 LSM_OBSERVED_SYSCALL_COUNT,
                 DIRECT_OBSERVED_SYSCALL_COUNT,
                 ASYNC_BYPASS_SYSCALL_COUNT);
        log_msg("   All remaining syscalls: SECCOMP_RET_TRACE");
    }
    log_msgf("   Filter instructions: %u", (unsigned int)prog.len);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        log_msgf("ERROR: PR_SET_NO_NEW_PRIVS failed: %s", strerror(errno));
        return -1;
    }
    log_msg("✅ PR_SET_NO_NEW_PRIVS: OK");

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
        log_msgf("ERROR: PR_SET_SECCOMP failed: %s", strerror(errno));
        return -1;
    }

    log_msgf("✅ Seccomp filter installed (%u instructions)",
             (unsigned int)prog.len);
    if (routing == SECCOMP_ROUTING_ALL_TRACE) {
        log_msg("   0 syscalls bypass ptrace");
    } else {
        log_msgf("   %d syscalls bypass ptrace; all others trigger ptrace_notify",
                 PTRACE_BYPASS_SYSCALL_COUNT);
    }
    return 0;
}

static char* cleanup_path(const char *original_path) {
    static char cleaned_path[MAX_PATH];

    log_msgf("Original PATH: %s", original_path);

    const char *src = original_path;
    char *dst = cleaned_path;
    int found_sygma = 0;

    if (strncmp(src, "/opt/sygma:", 9) == 0) {
        src += 9;
        found_sygma = 1;
    }

    while (*src) {
        if (strncmp(src, ":/opt/sygma:", 10) == 0) {
            src += 9;
            found_sygma = 1;
        } else if (strncmp(src, ":/opt/sygma", 9) == 0 && src[9] == '\0') {

            found_sygma = 1;
            break;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';

    if (cleaned_path[0] == '\0') {
        strcpy(cleaned_path, "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
        log_msgf("✅ PATH cleaned (was only sygma): %s", cleaned_path);
        return cleaned_path;
    }

    if (found_sygma) {
        log_msgf("✅ PATH cleaned (removed /opt/sygma): %s", cleaned_path);
    } else {
        log_msg("⚠️ /opt/sygma not found in PATH");
    }

    return cleaned_path;
}

static void update_path_in_env(char **envp) {
    log_msg("🔧 Cleaning up PATH in environment...");

    for (int i = 0; envp[i] != NULL; i++) {
        if (strncmp(envp[i], "PATH=", 5) == 0) {
            char *original_path = envp[i] + 5;
            char *cleaned = cleanup_path(original_path);

            static char new_path_env[MAX_PATH];
            snprintf(new_path_env, sizeof(new_path_env), "PATH=%s", cleaned);
            envp[i] = new_path_env;

            log_msg("✅ PATH updated in environment");
            return;
        }
    }

    log_msg("⚠️ WARNING: PATH not found in environment");
}

static int execute_binary_replacement(char **argv, char **envp) {
    log_msg("🔧 Mode: Binary Replacement (Minimal Image)");

    if (g_found_binary_path[0] == '\0') {
        log_msg("❌ ERROR: Binary path not found");
        return 1;
    }

    char real_path[MAX_PATH];
    if (real_binary_path(real_path, sizeof(real_path), g_found_binary_path) != 0) {
        log_msg("❌ ERROR: Real binary path is too long");
        return 1;
    }

    log_msgf("Binary path: %s", g_found_binary_path);
    log_msgf("Real binary path: %s", real_path);

    log_msg("========================================");
    log_msgf("🚀 Executing: %s", real_path);
    log_msg("========================================");

    execve(real_path, argv, envp);

    log_msgf("❌ ERROR: execve failed: %s", strerror(errno));
    return 1;
}

static int execute_path_hijacking(char **argv, char **envp) {
    log_msg("🔧 Mode: PATH Hijacking (Full Image)");

    update_path_in_env(envp);

    char *target_binary = getenv("SYGMA_TARGET_BINARY");
    char *exec_target;

    if (target_binary != NULL && strlen(target_binary) > 0) {
        exec_target = target_binary;
        log_msgf("✅ Using SYGMA_TARGET_BINARY: %s", exec_target);
    } else {
        exec_target = argv[0];
        log_msgf("⚠️ SYGMA_TARGET_BINARY not set, using argv[0]: %s", exec_target);
    }

    char *path_env = NULL;
    for (int i = 0; envp[i] != NULL; i++) {
        if (strncmp(envp[i], "PATH=", 5) == 0) {
            path_env = envp[i] + 5;
            break;
        }
    }

    if (path_env == NULL) {
        log_msg("❌ ERROR: PATH not found in environment");
        return 1;
    }

    log_msg("========================================");
    log_msgf("🔍 Searching for: %s", exec_target);
    log_msgf("   PATH: %s", path_env);
    log_msg("========================================");

    char path_copy[MAX_PATH];
    strncpy(path_copy, path_env, sizeof(path_copy) - 1);
    path_copy[sizeof(path_copy) - 1] = '\0';

    char full_path[MAX_PATH];
    char *dir = strtok(path_copy, ":");
    int found = 0;

    while (dir != NULL) {
        snprintf(full_path, sizeof(full_path), "%s/%s", dir, exec_target);

        log_msgf("   Trying: %s", full_path);

        struct stat st;
        if (stat(full_path, &st) == 0) {
            if (S_ISREG(st.st_mode) && (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
                log_msgf("✅ Found: %s", full_path);
                found = 1;
                break;
            } else {
                log_msgf("   → Found but not executable");
            }
        }

        dir = strtok(NULL, ":");
    }

    if (!found) {
        log_msgf("❌ ERROR: '%s' not found in PATH", exec_target);
        log_msgf("   PATH: %s", path_env);

        _exit(127);
    }

    log_msg("========================================");
    log_msgf("🚀 Executing: %s", full_path);
    log_msg("========================================");

    execve(full_path, argv, envp);

    log_msg("========================================");
    log_msg("❌ ERROR: execve failed");
    log_msgf("   errno: %d (%s)", errno, strerror(errno));
    log_msgf("   file: %s", full_path);
    log_msg("========================================");
    _exit(126);

    return 1;
}

int main(int argc, char **argv, char **envp) {
    log_msg("========================================");
    log_msg("========== SYGMA WRAPPER START ==========");
    log_msg("========================================");

    log_msgf("PID: %d, PPID: %d", getpid(), getppid());
    log_msgf("Called as: %s", argv[0]);

    log_msgf("Arguments (%d):", argc);
    for (int i = 0; i < argc && i < 10; i++) {
        log_msgf("  argv[%d]: %s", i, argv[i]);
    }

    char *sygma_mode = getenv("SYGMA_MODE");
    char *sygma_binary = getenv("SYGMA_TARGET_BINARY");
    char *sygma_binary_path = getenv("SYGMA_BINARY_PATH");
    char *sygma_method = getenv("SYGMA_REPLACEMENT_METHOD");
    char *sygma_seccomp_routing = getenv(SYGMA_SECCOMP_ROUTING_ENV);

    log_msg("========================================");
    log_msg("Environment Variables:");
    if (sygma_mode) log_msgf("  SYGMA_MODE: %s", sygma_mode);
    if (sygma_binary) log_msgf("  SYGMA_TARGET_BINARY: %s", sygma_binary);
    if (sygma_binary_path) log_msgf("  SYGMA_BINARY_PATH: %s", sygma_binary_path);
    if (sygma_method) log_msgf("  SYGMA_REPLACEMENT_METHOD: %s", sygma_method);
    log_msgf("  %s: %s", SYGMA_SECCOMP_ROUTING_ENV,
             (sygma_seccomp_routing != NULL && sygma_seccomp_routing[0] != '\0')
                 ? sygma_seccomp_routing
                 : SYGMA_SECCOMP_ROUTING_SELECTIVE);
    log_msg("========================================");

    int use_binary_replacement = 0;

    if (argv[0][0] == '/') {
        char real_path[MAX_PATH];
        snprintf(real_path, sizeof(real_path), "%s.real", argv[0]);

        if (access(real_path, X_OK) == 0) {
            use_binary_replacement = 1;
            if (copy_path(g_found_binary_path, sizeof(g_found_binary_path), argv[0]) != 0) {
                log_msg("❌ ERROR: Binary path is too long");
                return 1;
            }
            log_msgf("✅ Absolute path + .real file exists → Binary Replacement (path: %s)", argv[0]);
        } else {
            use_binary_replacement = 0;
            log_msg("✅ Absolute path but no .real file → PATH Hijacking");
        }
    } else {

        char *path_env = getenv("PATH");
        if (!path_env) {
            path_env = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
        }

        char found_path[MAX_PATH] = {0};
        char path_copy[MAX_PATH];
        if (copy_path(path_copy, sizeof(path_copy), path_env) != 0) {
            log_msg("❌ ERROR: PATH is too long");
            return 1;
        }

        char *dir = strtok(path_copy, ":");
        while (dir != NULL) {

            if (strncmp(dir, "/opt/sygma", 8) == 0) {
                log_msgf("   Skipping /opt/sygma directory: %s", dir);
                dir = strtok(NULL, ":");
                continue;
            }

            char candidate[MAX_PATH];
            int candidate_length = snprintf(candidate, sizeof(candidate), "%s/%s", dir, argv[0]);
            if (candidate_length < 0 || (size_t)candidate_length >= sizeof(candidate)) {
                dir = strtok(NULL, ":");
                continue;
            }

            if (access(candidate, X_OK) == 0) {
                if (copy_path(found_path, sizeof(found_path), candidate) != 0) {
                    log_msg("❌ ERROR: Found binary path is too long");
                    return 1;
                }
                log_msgf("   Found binary at: %s", candidate);
                break;
            }
            dir = strtok(NULL, ":");
        }

        if (found_path[0] != '\0') {
            char real_path[MAX_PATH];
            if (real_binary_path(real_path, sizeof(real_path), found_path) != 0) {
                log_msg("❌ ERROR: Real binary path is too long");
                return 1;
            }

            if (access(real_path, X_OK) == 0) {
                use_binary_replacement = 1;
                if (copy_path(g_found_binary_path, sizeof(g_found_binary_path), found_path) != 0) {
                    log_msg("❌ ERROR: Binary path is too long");
                    return 1;
                }
                log_msgf("✅ Found %s with .real file → Binary Replacement", found_path);
            } else {
                use_binary_replacement = 0;
                log_msgf("✅ Found %s but no .real file → PATH Hijacking", found_path);
            }
        }
    }

    log_msg("========================================");
    log_msg("🛑 Raising SIGSTOP for tracer attach...");
    raise(SIGSTOP);

    log_msg("✅ Resumed by attached tracer");

    if (install_seccomp_filter(sygma_seccomp_routing) != 0) {
        log_msg("❌ ERROR: Seccomp installation failed");
        return 1;
    }
    log_msg("========================================");

    if (use_binary_replacement) {
        return execute_binary_replacement(argv, envp);
    } else {
        return execute_path_hijacking(argv, envp);
    }
}

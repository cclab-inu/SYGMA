// wrapper.c - Universal Binary Wrapper (Updated)
// Method detection via SYGMA_REPLACEMENT_METHOD environment variable

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

// ========================================
// BPF Macros
// ========================================

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#define BPF_STMT(code, k) { (unsigned short)(code), 0, 0, k }
#define BPF_JUMP(code, k, jt, jf) { (unsigned short)(code), jt, jf, k }

static char g_found_binary_path[MAX_PATH] = {0};

// ========================================
// Logging
// ========================================

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

// ========================================
// Tracer Wait
// ========================================

static int wait_for_tracer(void) {
    log_msg("⏳ Waiting for tracer to attach...");
    
    int max_attempts = 500;  // 5 seconds
    
    for (int i = 0; i < max_attempts; i++) {
        int fd = open("/proc/self/status", O_RDONLY);
        if (fd < 0) {
            log_msg("ERROR: Cannot open /proc/self/status");
            return -1;
        }
        
        char status_buf[4096];
        ssize_t n = read(fd, status_buf, sizeof(status_buf) - 1);
        close(fd);
        
        if (n <= 0) {
            log_msg("ERROR: Cannot read /proc/self/status");
            return -1;
        }
        
        status_buf[n] = '\0';
        
        char *line = status_buf;
        while (line && *line) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                int tracer_pid = 0;
                if (sscanf(line + 10, "%d", &tracer_pid) == 1 && tracer_pid > 0) {
                    log_msgf("✅ Tracer attached (PID: %d, attempt: %d)", tracer_pid, i + 1);
                    return 0;
                }
                break;
            }
            line = strchr(line, '\n');
            if (line) line++;
        }
        
        struct timespec ts = {0, 10000000};  // 10ms
        nanosleep(&ts, NULL);
    }
    
    log_msg("⚠️ WARNING: Tracer not attached after 5s");
    return -1;
}

// ========================================
// Seccomp Installation (Selective TRACE)
// ========================================

static int install_seccomp_filter(void) {
    log_msg("🔒 Installing selective seccomp filter...");
    log_msg("   Excluded syscalls (ALLOW): 0,1,5,18,20,24,40,44,45,46,47,202,232,257,262,271");
    log_msg("   All other syscalls: TRACE");
    
    struct seccomp_data {
        int nr;
        __u32 arch;
        __u64 instruction_pointer;
        __u64 args[6];
    };
    
    struct sock_filter filter[] = {
        // Load syscall number into accumulator
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        
        // ========================================
        // Excluded Syscalls (LSM-BPF or Async)
        // ========================================
        
        // 0: read (file_permission)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        // 1: write (file_permission)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        // 5: fstat (security_inode_getattr)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 5, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        // 9: mmap (security_mmap_file)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 9, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        // 17: pread64 (security_file_permission)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 17, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        // 18: pwrite64 (file_permission)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 18, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        // 20: writev (file_permission)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 20, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        // 24: (Skip: async)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 24, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        // 40: sendfile (file_permission)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 40, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        // 44: sendto (socket_sendmsg)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 44, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        // 45: recvfrom (socket_recvmsg)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 45, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        // 46: sendmsg (security_socket_sendmsg)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 46, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        // 47: recvmsg (socket_recvmsg)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 47, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        // 54: setsockopt (security_socket_setsockopt)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 54, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

        // 59: execve (security_bprm_check)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 59, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        // 202: futex (Skip: async)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 202, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        // 232: epoll_wait (Skip: async)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 232, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        // 257: openat (security_file_alloc)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 257, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        // 262: newfstatat (security_inode_getattr)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 262, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        // 271: ppoll (Skip: async)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 271, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        // 288: accept4 (security_socket_accept)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 288, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        // ========================================
        // Default: TRACE for all other syscalls
        // ========================================
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
    };
    
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        log_msgf("ERROR: PR_SET_NO_NEW_PRIVS failed: %s", strerror(errno));
        return -1;
    }
    log_msg("✅ PR_SET_NO_NEW_PRIVS: OK");

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
        log_msgf("ERROR: PR_SET_SECCOMP failed: %s", strerror(errno));
        return -1;
    }
    
    log_msgf("✅ Seccomp filter installed (%lu instructions)", sizeof(filter) / sizeof(filter[0]));
    log_msg("   16 syscalls excluded (ALLOW), others will TRACE");

    return 0;
}

// ========================================
// PATH Cleanup
// ========================================

static char* cleanup_path(const char *original_path) {
    static char cleaned_path[MAX_PATH];
    
    log_msgf("Original PATH: %s", original_path);
    
    const char *src = original_path;
    char *dst = cleaned_path;
    int found_sygma = 0;
    
    // ⭐ prefix : /opt/sygma:/usr/... → /usr/...
    if (strncmp(src, "/opt/sygma:", 9) == 0) {
        src += 9;
        found_sygma = 1;
    }
    
    //   :/opt/sygma 
    while (*src) {
        if (strncmp(src, ":/opt/sygma:", 10) == 0) {
            src += 9;   // ":/opt/sygma"  (:  )
            found_sygma = 1;
        } else if (strncmp(src, ":/opt/sygma", 9) == 0 && src[9] == '\0') {
            //  :/opt/sygma
            found_sygma = 1;
            break;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
    
    // PATH /opt/sygma  
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

// ========================================
// Binary Replacement Logic
// ========================================

static int execute_binary_replacement(char **argv, char **envp) {
    log_msg("🔧 Mode: Binary Replacement (Minimal Image)");
    
    // ⭐    
    if (g_found_binary_path[0] == '\0') {
        log_msg("❌ ERROR: Binary path not found");
        return 1;
    }
    
    char real_path[MAX_PATH];
    snprintf(real_path, sizeof(real_path), "%s.real", g_found_binary_path);
    
    log_msgf("Binary path: %s", g_found_binary_path);
    log_msgf("Real binary path: %s", real_path);
    
    log_msg("========================================");
    log_msgf("🚀 Executing: %s", real_path);
    log_msg("========================================");
    
    execve(real_path, argv, envp);
    
    log_msgf("❌ ERROR: execve failed: %s", strerror(errno));
    return 1;
}

// ========================================
// PATH Hijacking Logic
// ========================================

static int execute_path_hijacking(char **argv, char **envp) {
    log_msg("🔧 Mode: PATH Hijacking (Full Image)");
    
    // PATH cleanup
    update_path_in_env(envp);
    
    // Target binary 
    char *target_binary = getenv("SYGMA_TARGET_BINARY");
    char *exec_target;
    
    if (target_binary != NULL && strlen(target_binary) > 0) {
        exec_target = target_binary;
        log_msgf("✅ Using SYGMA_TARGET_BINARY: %s", exec_target);
    } else {
        exec_target = argv[0];
        log_msgf("⚠️ SYGMA_TARGET_BINARY not set, using argv[0]: %s", exec_target);
    }
    
    // PATH  
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
    
    // PATH 
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
    
    // execve 
    log_msg("========================================");
    log_msg("❌ ERROR: execve failed");
    log_msgf("   errno: %d (%s)", errno, strerror(errno));
    log_msgf("   file: %s", full_path);
    log_msg("========================================");
    _exit(126);

    return 1;
}

// ========================================
// Main
// ========================================

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
    
    // ⭐  
    char *sygma_mode = getenv("SYGMA_MODE");
    char *sygma_binary = getenv("SYGMA_TARGET_BINARY");
    char *sygma_binary_path = getenv("SYGMA_BINARY_PATH");
    char *sygma_method = getenv("SYGMA_REPLACEMENT_METHOD");
    
    log_msg("========================================");
    log_msg("Environment Variables:");
    if (sygma_mode) log_msgf("  SYGMA_MODE: %s", sygma_mode);
    if (sygma_binary) log_msgf("  SYGMA_TARGET_BINARY: %s", sygma_binary);
    if (sygma_binary_path) log_msgf("  SYGMA_BINARY_PATH: %s", sygma_binary_path);
    if (sygma_method) log_msgf("  SYGMA_REPLACEMENT_METHOD: %s", sygma_method);
    log_msg("========================================");
    
    // ⭐⭐⭐ Method 
    int use_binary_replacement = 0;

    // 1.   
    if (argv[0][0] == '/') {
        char real_path[MAX_PATH];
        snprintf(real_path, sizeof(real_path), "%s.real", argv[0]);
        
        if (access(real_path, X_OK) == 0) {
            use_binary_replacement = 1;
            strncpy(g_found_binary_path, argv[0], sizeof(g_found_binary_path) - 1);  // ⭐   !
            log_msgf("✅ Absolute path + .real file exists → Binary Replacement (path: %s)", argv[0]);
        } else {
            use_binary_replacement = 0;
            log_msg("✅ Absolute path but no .real file → PATH Hijacking");
        }
    } else {
        // 2.    - PATH  /opt/sygma 
        char *path_env = getenv("PATH");
        if (!path_env) {
            path_env = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
        }
        
        char found_path[MAX_PATH] = {0};
        char path_copy[MAX_PATH];
        strncpy(path_copy, path_env, sizeof(path_copy) - 1);
        
        char *dir = strtok(path_copy, ":");
        while (dir != NULL) {
            // ⭐ /opt/sygma  
            if (strncmp(dir, "/opt/sygma", 8) == 0) {
                log_msgf("   Skipping /opt/sygma directory: %s", dir);
                dir = strtok(NULL, ":");
                continue;
            }
            
            char candidate[MAX_PATH];
            snprintf(candidate, sizeof(candidate), "%s/%s", dir, argv[0]);
            
            if (access(candidate, X_OK) == 0) {
                strncpy(found_path, candidate, sizeof(found_path) - 1);
                log_msgf("   Found binary at: %s", candidate);
                break;
            }
            dir = strtok(NULL, ":");
        }
        
        if (found_path[0] != '\0') {
            char real_path[MAX_PATH];
            snprintf(real_path, sizeof(real_path), "%s.real", found_path);
            
            if (access(real_path, X_OK) == 0) {
                use_binary_replacement = 1;
                strncpy(g_found_binary_path, found_path, sizeof(g_found_binary_path) - 1);  // ⭐ 
                log_msgf("✅ Found %s with .real file → Binary Replacement", found_path);
            } else {
                use_binary_replacement = 0;
                log_msgf("✅ Found %s but no .real file → PATH Hijacking", found_path);
            }
        }
    }

    // ⭐ Common setup: SIGSTOP + Tracer wait + Seccomp
    log_msg("========================================");
    log_msg("🛑 Raising SIGSTOP for tracer attach...");
    raise(SIGSTOP);
    log_msg("🔄 Resumed from SIGSTOP");
    
    if (wait_for_tracer() != 0) {
        log_msg("⚠️ WARNING: Continuing without tracer confirmation");
    }
    
    if (install_seccomp_filter() != 0) {
        log_msg("❌ ERROR: Seccomp installation failed");
        return 1;
    }
    log_msg("========================================");
    
    // ⭐ Execute based on method
    if (use_binary_replacement) {
        return execute_binary_replacement(argv, envp);
    } else {
        return execute_path_hijacking(argv, envp);
    }
}

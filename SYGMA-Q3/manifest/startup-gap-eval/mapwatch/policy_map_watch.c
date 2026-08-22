// SPDX-License-Identifier: Apache-2.0
// Observe Tetragon's policy-filter map-in-map using only the bpf(2) ABI.

#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <linux/bpf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if !defined(__x86_64__)
#error "policy_map_watch supports x86-64 only"
#endif

#ifndef __NR_bpf
#define __NR_bpf 321
#endif

#define DEFAULT_MAP_PATH "/sys/fs/bpf/tetragon/policy_filter_maps"
#define DEFAULT_APP_BIN_MAP "/sys/fs/bpf/sygma/app_sc_bins"
#define DEFAULT_APP_COUNT_MAP "/sys/fs/bpf/sygma/app_sc_counts"
#define DEFAULT_APP_META_MAP "/sys/fs/bpf/sygma/app_sc_meta"
#define DEFAULT_APP_FIRST_SEEN_MAP "/sys/fs/bpf/sygma/app_sc_first_seen"
#define APP_SYSCALL_BUCKET_NS UINT64_C(100000)
#define DEFAULT_POLL_US UINT64_C(1000)
#define DEFAULT_TIMEOUT_MS UINT64_C(10000)
#define MAX_POLL_US UINT64_C(60000000)
#define MAX_TIMEOUT_MS UINT64_C(86400000)
#define MAX_ENUM_ENTRIES UINT32_C(1048576)
#define NS_PER_US UINT64_C(1000)
#define NS_PER_MS UINT64_C(1000000)

struct timestamp {
    uint64_t realtime_ns;
    uint64_t boottime_ns;
};

struct key_array {
    uint64_t *items;
    size_t count;
};

struct u64_set {
    uint64_t *slots;
    unsigned char *used;
    size_t capacity;
    size_t count;
};

struct app_syscall_bin_key {
    uint64_t cgroup_id;
    uint64_t bucket;
};

struct app_syscall_count_key {
    uint64_t cgroup_id;
    uint32_t syscall_nr;
    uint32_t padding;
};

struct app_syscall_meta_value {
    uint64_t total;
    uint64_t first_boottime_ns;
    uint64_t last_boottime_ns;
    uint32_t root_tgid;
    uint32_t padding;
};

struct app_boundary_counts {
    uint64_t definite;
    uint64_t possible;
    uint64_t observed;
    uint64_t matching_bins;
    uint64_t distinct_definite;
    uint64_t distinct_possible;
};

struct options {
    const char *map_path;
    const char *app_bin_map_path;
    const char *app_count_map_path;
    const char *app_meta_map_path;
    const char *app_first_seen_map_path;
    uint32_t policy_id;
    uint64_t poll_us;
    uint64_t timeout_ms;
    bool have_policy_id;
    bool inspect_map;
    bool lookup_ns_value;
    bool lookup_sygma_misses;
    bool lookup_app_syscalls;
    bool cleanup_app_syscalls;
    bool have_cgroup_id;
    uint64_t cgroup_id;
    bool have_mnt_ns;
    bool have_pid_ns;
    uint32_t mnt_ns;
    uint32_t pid_ns;
    bool have_syscall_nr;
    bool have_phase;
    bool have_tgid;
    uint32_t syscall_nr;
    uint32_t phase;
    uint32_t tgid;
    bool once;
    bool exit_after_insert;
    bool have_before_boottime_ns;
    uint64_t before_boottime_ns;
};

static uint64_t timespec_to_ns(const struct timespec *ts)
{
    return (uint64_t)ts->tv_sec * UINT64_C(1000000000) +
           (uint64_t)ts->tv_nsec;
}

static int read_timestamp(struct timestamp *ts)
{
    struct timespec real;
    struct timespec boot;

    if (clock_gettime(CLOCK_REALTIME, &real) != 0)
        return -1;
    if (clock_gettime(CLOCK_BOOTTIME, &boot) != 0)
        return -1;

    ts->realtime_ns = timespec_to_ns(&real);
    ts->boottime_ns = timespec_to_ns(&boot);
    return 0;
}

static long raw_syscall3(long number, long arg1, long arg2, long arg3)
{
    register long rax __asm__("rax") = number;
    register long rdi __asm__("rdi") = arg1;
    register long rsi __asm__("rsi") = arg2;
    register long rdx __asm__("rdx") = arg3;

    __asm__ volatile("syscall"
                     : "+a"(rax)
                     : "D"(rdi), "S"(rsi), "d"(rdx)
                     : "rcx", "r11", "memory");
    return rax;
}

static int raw_bpf(enum bpf_cmd command, union bpf_attr *attr)
{
    long rc = raw_syscall3(__NR_bpf, command, (long)(uintptr_t)attr,
                           (long)sizeof(*attr));

    if (rc < 0 && rc >= -4095) {
        errno = (int)-rc;
        return -1;
    }
    return (int)rc;
}

static int bpf_obj_get(const char *path)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.pathname = (uint64_t)(uintptr_t)path;
    return raw_bpf(BPF_OBJ_GET, &attr);
}

static int bpf_map_lookup(int fd, const void *key, void *value)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)fd;
    attr.key = (uint64_t)(uintptr_t)key;
    attr.value = (uint64_t)(uintptr_t)value;
    return raw_bpf(BPF_MAP_LOOKUP_ELEM, &attr);
}

static int bpf_map_get_next_key(int fd, const void *key, void *next_key)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)fd;
    attr.key = (uint64_t)(uintptr_t)key;
    attr.next_key = (uint64_t)(uintptr_t)next_key;
    return raw_bpf(BPF_MAP_GET_NEXT_KEY, &attr);
}

static int bpf_map_delete(int fd, const void *key)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)fd;
    attr.key = (uint64_t)(uintptr_t)key;
    return raw_bpf(BPF_MAP_DELETE_ELEM, &attr);
}

static int bpf_map_get_fd_by_id(uint32_t id)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.map_id = id;
    return raw_bpf(BPF_MAP_GET_FD_BY_ID, &attr);
}

static int bpf_map_get_info(int fd, struct bpf_map_info *info)
{
    union bpf_attr attr;

    memset(info, 0, sizeof(*info));
    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd = (uint32_t)fd;
    attr.info.info_len = (uint32_t)sizeof(*info);
    attr.info.info = (uint64_t)(uintptr_t)info;
    return raw_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr);
}

static int parse_u64(const char *text, uint64_t min, uint64_t max,
                     uint64_t *value)
{
    char *end = NULL;
    unsigned long long parsed;

    if (text == NULL || text[0] == '\0' || text[0] == '-')
        return -1;

    errno = 0;
    parsed = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed < min ||
        parsed > max)
        return -1;

    *value = (uint64_t)parsed;
    return 0;
}

static void usage(FILE *stream, const char *program)
{
    fprintf(stream,
            "Usage: %s --policy-id N [--map-path PATH] [--once]\n"
            "       [--poll-us N] [--timeout-ms N] [--exit-after-insert]\n"
            "       %s --inspect-map PATH\n"
            "       %s --lookup-ns-value PATH --mnt-ns N --pid-ns N\n"
            "       %s --lookup-sygma-misses PATH --mnt-ns N --pid-ns N\n"
            "          --syscall-nr N --phase N [--tgid N]\n"
            "       %s --lookup-app-syscalls --cgroup-id N [--cleanup]\n"
            "          [--before-boottime-ns N]\n"
            "          [--app-bin-map PATH] [--app-count-map PATH]\n"
            "          [--app-meta-map PATH] [--app-first-seen-map PATH]\n"
            "Defaults: --map-path %s --poll-us 1000 --timeout-ms 10000\n",
            program, program, program, program, program, DEFAULT_MAP_PATH);
}

static int parse_options(int argc, char **argv, struct options *options)
{
    int i;

    memset(options, 0, sizeof(*options));
    options->map_path = DEFAULT_MAP_PATH;
    options->app_bin_map_path = DEFAULT_APP_BIN_MAP;
    options->app_count_map_path = DEFAULT_APP_COUNT_MAP;
    options->app_meta_map_path = DEFAULT_APP_META_MAP;
    options->app_first_seen_map_path = DEFAULT_APP_FIRST_SEEN_MAP;
    options->poll_us = DEFAULT_POLL_US;
    options->timeout_ms = DEFAULT_TIMEOUT_MS;

    for (i = 1; i < argc; i++) {
        uint64_t parsed;

        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(stdout, argv[0]);
            exit(0);
        }

        if (strcmp(argv[i], "--once") == 0) {
            options->once = true;
            continue;
        }

        if (strcmp(argv[i], "--exit-after-insert") == 0) {
            options->exit_after_insert = true;
            continue;
        }

        if (strcmp(argv[i], "--lookup-app-syscalls") == 0) {
            options->lookup_app_syscalls = true;
            continue;
        }

        if (strcmp(argv[i], "--cleanup") == 0) {
            options->cleanup_app_syscalls = true;
            continue;
        }

        if (strcmp(argv[i], "--cgroup-id") == 0) {
            if (++i >= argc ||
                parse_u64(argv[i], 1, UINT64_MAX,
                          &options->cgroup_id) != 0) {
                fprintf(stderr, "invalid --cgroup-id value\n");
                return -1;
            }
            options->have_cgroup_id = true;
            continue;
        }

        if (strcmp(argv[i], "--before-boottime-ns") == 0) {
            if (++i >= argc ||
                parse_u64(argv[i], 0, UINT64_MAX,
                          &options->before_boottime_ns) != 0) {
                fprintf(stderr, "invalid --before-boottime-ns value\n");
                return -1;
            }
            options->have_before_boottime_ns = true;
            continue;
        }

        if (strcmp(argv[i], "--app-bin-map") == 0 ||
            strcmp(argv[i], "--app-count-map") == 0 ||
            strcmp(argv[i], "--app-meta-map") == 0 ||
            strcmp(argv[i], "--app-first-seen-map") == 0) {
            const char *kind = argv[i];
            if (++i >= argc || argv[i][0] == '\0') {
                fprintf(stderr, "invalid application map path\n");
                return -1;
            }
            if (strcmp(kind, "--app-bin-map") == 0)
                options->app_bin_map_path = argv[i];
            else if (strcmp(kind, "--app-count-map") == 0)
                options->app_count_map_path = argv[i];
            else if (strcmp(kind, "--app-meta-map") == 0)
                options->app_meta_map_path = argv[i];
            else
                options->app_first_seen_map_path = argv[i];
            continue;
        }

        if (strcmp(argv[i], "--inspect-map") == 0) {
            if (++i >= argc || argv[i][0] == '\0') {
                fprintf(stderr, "invalid --inspect-map path\n");
                return -1;
            }
            options->map_path = argv[i];
            options->inspect_map = true;
            continue;
        }

        if (strcmp(argv[i], "--lookup-ns-value") == 0) {
            if (++i >= argc || argv[i][0] == '\0') {
                fprintf(stderr, "invalid --lookup-ns-value path\n");
                return -1;
            }
            options->map_path = argv[i];
            options->lookup_ns_value = true;
            continue;
        }

        if (strcmp(argv[i], "--lookup-sygma-misses") == 0) {
            if (++i >= argc || argv[i][0] == '\0') {
                fprintf(stderr, "invalid --lookup-sygma-misses path\n");
                return -1;
            }
            options->map_path = argv[i];
            options->lookup_sygma_misses = true;
            continue;
        }

        if (strcmp(argv[i], "--syscall-nr") == 0 ||
            strcmp(argv[i], "--phase") == 0) {
            bool is_syscall = strcmp(argv[i], "--syscall-nr") == 0;

            if (++i >= argc ||
                parse_u64(argv[i], 0, UINT32_MAX, &parsed) != 0) {
                fprintf(stderr, "invalid syscall/phase value\n");
                return -1;
            }
            if (is_syscall) {
                options->syscall_nr = (uint32_t)parsed;
                options->have_syscall_nr = true;
            } else {
                options->phase = (uint32_t)parsed;
                options->have_phase = true;
            }
            continue;
        }

        if (strcmp(argv[i], "--tgid") == 0) {
            if (++i >= argc ||
                parse_u64(argv[i], 1, UINT32_MAX, &parsed) != 0) {
                fprintf(stderr, "invalid --tgid value\n");
                return -1;
            }
            options->tgid = (uint32_t)parsed;
            options->have_tgid = true;
            continue;
        }

        if (strcmp(argv[i], "--mnt-ns") == 0 ||
            strcmp(argv[i], "--pid-ns") == 0) {
            bool is_mnt = strcmp(argv[i], "--mnt-ns") == 0;

            if (++i >= argc ||
                parse_u64(argv[i], 1, UINT32_MAX, &parsed) != 0) {
                fprintf(stderr, "invalid namespace inode value\n");
                return -1;
            }
            if (is_mnt) {
                options->mnt_ns = (uint32_t)parsed;
                options->have_mnt_ns = true;
            } else {
                options->pid_ns = (uint32_t)parsed;
                options->have_pid_ns = true;
            }
            continue;
        }

        if (strcmp(argv[i], "--policy-id") == 0) {
            if (++i >= argc ||
                parse_u64(argv[i], 0, UINT32_MAX, &parsed) != 0) {
                fprintf(stderr, "invalid --policy-id value\n");
                return -1;
            }
            options->policy_id = (uint32_t)parsed;
            options->have_policy_id = true;
            continue;
        }

        if (strncmp(argv[i], "--policy-id=", 12) == 0) {
            if (parse_u64(argv[i] + 12, 0, UINT32_MAX, &parsed) != 0) {
                fprintf(stderr, "invalid --policy-id value\n");
                return -1;
            }
            options->policy_id = (uint32_t)parsed;
            options->have_policy_id = true;
            continue;
        }

        if (strcmp(argv[i], "--map") == 0 ||
            strcmp(argv[i], "--map-path") == 0) {
            if (++i >= argc || argv[i][0] == '\0') {
                fprintf(stderr, "invalid map path\n");
                return -1;
            }
            options->map_path = argv[i];
            continue;
        }

        if (strcmp(argv[i], "--poll-us") == 0 ||
            strcmp(argv[i], "--interval-us") == 0) {
            if (++i >= argc ||
                parse_u64(argv[i], 1, MAX_POLL_US, &options->poll_us) != 0) {
                fprintf(stderr, "invalid polling interval\n");
                return -1;
            }
            continue;
        }

        if (strcmp(argv[i], "--timeout-ms") == 0) {
            if (++i >= argc ||
                parse_u64(argv[i], 1, MAX_TIMEOUT_MS,
                          &options->timeout_ms) != 0) {
                fprintf(stderr, "invalid --timeout-ms value\n");
                return -1;
            }
            continue;
        }

        fprintf(stderr, "unknown argument: %s\n", argv[i]);
        return -1;
    }

    if (options->inspect_map &&
        (options->have_policy_id || options->once ||
         options->exit_after_insert || options->lookup_ns_value ||
         options->lookup_sygma_misses || options->lookup_app_syscalls)) {
        fprintf(stderr,
                "--inspect-map cannot be combined with policy watch options\n");
        return -1;
    }
    if (options->lookup_ns_value &&
        (options->have_policy_id || options->once ||
         options->exit_after_insert || options->inspect_map ||
         options->lookup_sygma_misses ||
         !options->have_mnt_ns || !options->have_pid_ns)) {
        fprintf(stderr, "--lookup-ns-value requires only --mnt-ns and --pid-ns\n");
        return -1;
    }
    if (options->lookup_sygma_misses &&
        (options->have_policy_id || options->once ||
         options->exit_after_insert || options->inspect_map ||
         options->lookup_ns_value || !options->have_mnt_ns ||
         !options->have_pid_ns || !options->have_syscall_nr ||
         !options->have_phase)) {
        fprintf(stderr, "invalid --lookup-sygma-misses arguments\n");
        return -1;
    }
    if (options->lookup_app_syscalls &&
        (options->have_policy_id || options->once ||
         options->exit_after_insert || options->inspect_map ||
         options->lookup_ns_value || options->lookup_sygma_misses ||
         !options->have_cgroup_id)) {
        fprintf(stderr, "--lookup-app-syscalls requires --cgroup-id only\n");
        return -1;
    }
    if (options->cleanup_app_syscalls && !options->lookup_app_syscalls) {
        fprintf(stderr, "--cleanup requires --lookup-app-syscalls\n");
        return -1;
    }
    if (!options->lookup_ns_value && !options->lookup_sygma_misses &&
        (options->have_mnt_ns || options->have_pid_ns)) {
        fprintf(stderr, "--mnt-ns/--pid-ns require --lookup-ns-value\n");
        return -1;
    }
    if (!options->lookup_sygma_misses &&
        (options->have_syscall_nr || options->have_phase || options->have_tgid)) {
        fprintf(stderr,
                "--syscall-nr/--phase/--tgid require --lookup-sygma-misses\n");
        return -1;
    }
    if (!options->inspect_map && !options->lookup_ns_value &&
        !options->lookup_sygma_misses && !options->lookup_app_syscalls &&
        !options->have_policy_id) {
        fprintf(stderr, "--policy-id is required\n");
        return -1;
    }
    if (options->once && options->exit_after_insert) {
        fprintf(stderr, "--once and --exit-after-insert are mutually exclusive\n");
        return -1;
    }

    return 0;
}

static void json_string(const char *value)
{
    const unsigned char *p = (const unsigned char *)value;

    putchar('"');
    while (*p != '\0') {
        switch (*p) {
        case '"':
            fputs("\\\"", stdout);
            break;
        case '\\':
            fputs("\\\\", stdout);
            break;
        case '\b':
            fputs("\\b", stdout);
            break;
        case '\f':
            fputs("\\f", stdout);
            break;
        case '\n':
            fputs("\\n", stdout);
            break;
        case '\r':
            fputs("\\r", stdout);
            break;
        case '\t':
            fputs("\\t", stdout);
            break;
        default:
            if (*p < 0x20)
                printf("\\u%04x", (unsigned int)*p);
            else
                putchar((int)*p);
        }
        p++;
    }
    putchar('"');
}

static void emit_error(const char *stage, int error_number)
{
    struct timestamp ts = {0, 0};

    (void)read_timestamp(&ts);
    fputs("{\"schema_version\":1,\"event\":\"error\",\"stage\":", stdout);
    json_string(stage);
    printf(",\"errno\":%d,\"message\":", error_number);
    json_string(strerror(error_number));
    printf(",\"realtime_ns\":%" PRIu64 ",\"boottime_ns\":%" PRIu64 "}\n",
           ts.realtime_ns, ts.boottime_ns);
}

static void emit_map_info(const struct options *options,
                          const struct bpf_map_info *info,
                          const struct timestamp *ts)
{
    char name[BPF_OBJ_NAME_LEN + 1];

    memcpy(name, info->name, BPF_OBJ_NAME_LEN);
    name[BPF_OBJ_NAME_LEN] = '\0';
    printf("{\"schema_version\":1,\"event\":\"map_info\",\"map_path\":");
    json_string(options->map_path);
    fputs(",\"name\":", stdout);
    json_string(name);
    printf(",\"map_id\":%" PRIu32 ",\"map_type\":%" PRIu32 ","
           "\"key_size\":%" PRIu32 ",\"value_size\":%" PRIu32 ","
           "\"max_entries\":%" PRIu32 ",\"map_flags\":%" PRIu32 ","
           "\"realtime_ns\":%" PRIu64 ",\"boottime_ns\":%" PRIu64 "}\n",
           info->id, info->type, info->key_size, info->value_size,
           info->max_entries, info->map_flags, ts->realtime_ns,
           ts->boottime_ns);
}

static void emit_ns_value(const struct options *options, uint64_t value,
                          const struct bpf_map_info *info,
                          const struct timestamp *ts)
{
    printf("{\"schema_version\":1,\"event\":\"sygma_policy_evidence\"," 
           "\"map_path\":");
    json_string(options->map_path);
    printf(",\"map_id\":%" PRIu32 ",\"mnt_ns\":%" PRIu32 ","
           "\"pid_ns\":%" PRIu32 ",\"value\":%" PRIu64 ","
           "\"policy_evaluated\":%s,"
           "\"first_policy_evaluation_boottime_ns\":",
           info->id, options->mnt_ns, options->pid_ns, value,
           value > 1 ? "true" : "false");
    if (value > 1)
        printf("%" PRIu64, value);
    else
        fputs("null", stdout);
    printf(",\"observed_realtime_ns\":%" PRIu64 ","
           "\"observed_boottime_ns\":%" PRIu64 "}\n",
           ts->realtime_ns, ts->boottime_ns);
}

struct sygma_miss_key {
    uint32_t mnt_ns;
    uint32_t pid_ns;
    /* blocked_history: from_syscall; observed_misses: host TGID. */
    uint32_t subject;
    uint32_t to_syscall;
    uint32_t phase;
};

static int emit_sygma_misses(const struct options *options, int map_fd,
                             const struct bpf_map_info *info)
{
    struct sygma_miss_key current = {0};
    bool have_current = false;
    uint64_t total = 0;
    uint64_t matching_rows = 0;
    uint64_t other_phase_total = 0;
    uint64_t other_phase_rows = 0;
    uint64_t phase0_total = 0;
    size_t steps = 0;
    size_t max_steps = (size_t)info->max_entries * 2 + 16;
    struct timestamp ts;

    while (steps < max_steps) {
        struct sygma_miss_key next;
        uint32_t count = 0;

        if (bpf_map_get_next_key(map_fd,
                                 have_current ? (const void *)&current : NULL,
                                 &next) != 0) {
            if (errno == ENOENT)
                break;
            return -1;
        }
        if (next.mnt_ns == options->mnt_ns &&
            next.pid_ns == options->pid_ns &&
            (!options->have_tgid || next.subject == options->tgid) &&
            next.to_syscall == options->syscall_nr) {
            if (bpf_map_lookup(map_fd, &next, &count) != 0)
                return -1;
            if (next.phase == options->phase) {
                total += count;
                matching_rows++;
            } else {
                other_phase_total += count;
                other_phase_rows++;
            }
            if (next.phase == 0)
                phase0_total += count;
        }
        current = next;
        have_current = true;
        steps++;
    }
    if (steps == max_steps) {
        errno = ELOOP;
        return -1;
    }
    if (read_timestamp(&ts) != 0)
        return -1;
    printf("{\"schema_version\":2,\"event\":\"sygma_policy_observed_calls\","
           "\"map_path\":");
    json_string(options->map_path);
    printf(",\"map_id\":%" PRIu32 ",\"mnt_ns\":%" PRIu32 ","
           "\"pid_ns\":%" PRIu32 ",\"syscall_nr\":%" PRIu32 ","
           "\"tgid\":",
           info->id, options->mnt_ns, options->pid_ns, options->syscall_nr);
    if (options->have_tgid)
        printf("%" PRIu32, options->tgid);
    else
        fputs("null", stdout);
    printf(",\"phase\":%" PRIu32 ",\"matching_rows\":%" PRIu64 ","
           "\"count\":%" PRIu64 ",\"other_phase_rows\":%" PRIu64 ","
           "\"other_phase_count\":%" PRIu64 ",\"phase0_count\":%" PRIu64 ","
           "\"observed_realtime_ns\":%" PRIu64 ","
           "\"observed_boottime_ns\":%" PRIu64 "}\n",
           options->phase, matching_rows, total, other_phase_rows,
           other_phase_total, phase0_total, ts.realtime_ns, ts.boottime_ns);
    return 0;
}

static int compare_u64(const void *left, const void *right)
{
    uint64_t a = *(const uint64_t *)left;
    uint64_t b = *(const uint64_t *)right;

    return (a > b) - (a < b);
}

static void free_key_array(struct key_array *keys)
{
    free(keys->items);
    keys->items = NULL;
    keys->count = 0;
}

static int enumerate_keys(int map_fd, uint32_t max_entries,
                          struct key_array *keys)
{
    size_t max_steps;
    size_t steps = 0;
    size_t i;
    uint64_t current = 0;
    bool have_current = false;

    memset(keys, 0, sizeof(*keys));
    if (max_entries == 0 || max_entries > MAX_ENUM_ENTRIES) {
        errno = E2BIG;
        return -1;
    }

    max_steps = (size_t)max_entries * 2 + 16;
    keys->items = calloc(max_steps, sizeof(*keys->items));
    if (keys->items == NULL)
        return -1;

    while (steps < max_steps) {
        uint64_t next;

        if (bpf_map_get_next_key(map_fd,
                                 have_current ? (const void *)&current : NULL,
                                 &next) != 0) {
            if (errno == ENOENT)
                break;
            free_key_array(keys);
            return -1;
        }

        keys->items[keys->count++] = next;
        current = next;
        have_current = true;
        steps++;
    }

    if (steps == max_steps) {
        free_key_array(keys);
        errno = ELOOP;
        return -1;
    }

    qsort(keys->items, keys->count, sizeof(*keys->items), compare_u64);
    if (keys->count == 0)
        return 0;

    for (i = 1, steps = 1; i < keys->count; i++) {
        if (keys->items[i] != keys->items[steps - 1])
            keys->items[steps++] = keys->items[i];
    }
    keys->count = steps;
    return 0;
}

static uint64_t hash_u64(uint64_t value)
{
    value ^= value >> 30;
    value *= UINT64_C(0xbf58476d1ce4e5b9);
    value ^= value >> 27;
    value *= UINT64_C(0x94d049bb133111eb);
    value ^= value >> 31;
    return value;
}

static int set_allocate(struct u64_set *set, size_t capacity)
{
    set->slots = calloc(capacity, sizeof(*set->slots));
    set->used = calloc(capacity, sizeof(*set->used));
    if (set->slots == NULL || set->used == NULL) {
        free(set->slots);
        free(set->used);
        memset(set, 0, sizeof(*set));
        return -1;
    }
    set->capacity = capacity;
    set->count = 0;
    return 0;
}

static int set_init(struct u64_set *set, size_t expected)
{
    size_t capacity = 64;

    memset(set, 0, sizeof(*set));
    while (capacity < expected * 2 + 1) {
        if (capacity > SIZE_MAX / 2) {
            errno = EOVERFLOW;
            return -1;
        }
        capacity *= 2;
    }
    return set_allocate(set, capacity);
}

static int set_insert_without_grow(struct u64_set *set, uint64_t value)
{
    size_t mask = set->capacity - 1;
    size_t slot = (size_t)hash_u64(value) & mask;

    while (set->used[slot]) {
        if (set->slots[slot] == value)
            return 0;
        slot = (slot + 1) & mask;
    }

    set->used[slot] = 1;
    set->slots[slot] = value;
    set->count++;
    return 1;
}

static int set_grow(struct u64_set *set)
{
    struct u64_set replacement;
    size_t i;

    if (set->capacity > SIZE_MAX / 2) {
        errno = EOVERFLOW;
        return -1;
    }
    if (set_allocate(&replacement, set->capacity * 2) != 0)
        return -1;

    for (i = 0; i < set->capacity; i++) {
        if (set->used[i])
            (void)set_insert_without_grow(&replacement, set->slots[i]);
    }

    free(set->slots);
    free(set->used);
    *set = replacement;
    return 0;
}

/* Return 1 for a new key, 0 for an existing key, and -1 on allocation error. */
static int set_add(struct u64_set *set, uint64_t value)
{
    if ((set->count + 1) * 10 >= set->capacity * 7) {
        if (set_grow(set) != 0)
            return -1;
    }
    return set_insert_without_grow(set, value);
}

static void set_free(struct u64_set *set)
{
    free(set->slots);
    free(set->used);
    memset(set, 0, sizeof(*set));
}

static int sleep_until_boottime(uint64_t target_ns)
{
    struct timespec target;
    int rc;

    target.tv_sec = (time_t)(target_ns / UINT64_C(1000000000));
    target.tv_nsec = (long)(target_ns % UINT64_C(1000000000));
    do {
        rc = clock_nanosleep(CLOCK_BOOTTIME, TIMER_ABSTIME, &target, NULL);
    } while (rc == EINTR);

    if (rc != 0) {
        errno = rc;
        return -1;
    }
    return 0;
}

static void print_key_array(const struct key_array *keys)
{
    size_t i;

    putchar('[');
    for (i = 0; i < keys->count; i++) {
        if (i != 0)
            putchar(',');
        printf("%" PRIu64, keys->items[i]);
    }
    putchar(']');
}

static int read_app_boundary_counts(int map_fd,
                                    const struct bpf_map_info *map_info,
                                    uint64_t cgroup_id,
                                    uint64_t lower_boottime_ns,
                                    uint64_t upper_boottime_ns,
                                    struct app_boundary_counts *counts)
{
    struct app_syscall_bin_key current = {0, 0};
    bool have_current = false;
    size_t steps = 0;
    size_t max_steps = (size_t)map_info->max_entries * 2 + 16;

    memset(counts, 0, sizeof(*counts));
    while (steps < max_steps) {
        struct app_syscall_bin_key next;
        uint64_t value = 0;

        if (bpf_map_get_next_key(map_fd,
                                 have_current ? (const void *)&current : NULL,
                                 &next) != 0) {
            if (errno == ENOENT)
                break;
            return -1;
        }
        if (next.cgroup_id == cgroup_id) {
            uint64_t bucket_start;
            uint64_t bucket_end;

            if (bpf_map_lookup(map_fd, &next, &value) != 0)
                return -1;
            if (next.bucket > UINT64_MAX / APP_SYSCALL_BUCKET_NS) {
                errno = EOVERFLOW;
                return -1;
            }
            bucket_start = next.bucket * APP_SYSCALL_BUCKET_NS;
            bucket_end = bucket_start + APP_SYSCALL_BUCKET_NS;
            counts->observed += value;
            counts->matching_bins++;
            /* Entire bin precedes the last-known-absent lower bound. */
            if (bucket_end <= lower_boottime_ns)
                counts->definite += value;
            /* Any call in this bin may precede the first-present bound. */
            if (bucket_start <= upper_boottime_ns)
                counts->possible += value;
        }
        current = next;
        have_current = true;
        steps++;
    }
    if (steps == max_steps) {
        errno = ELOOP;
        return -1;
    }
    return 0;
}

static int count_bins_before(int bin_fd, const struct bpf_map_info *bin_info,
                             uint64_t cgroup_id, uint64_t before_boottime_ns,
                             uint64_t *out_count)
{
    struct app_syscall_bin_key current = {0, 0};
    bool have_current = false;
    size_t steps = 0;
    size_t max_steps = (size_t)bin_info->max_entries * 2 + 16;

    *out_count = 0;
    while (steps < max_steps) {
        struct app_syscall_bin_key next;
        uint64_t value = 0;

        if (bpf_map_get_next_key(bin_fd,
                                 have_current ? (const void *)&current : NULL,
                                 &next) != 0) {
            if (errno == ENOENT)
                break;
            return -1;
        }
        if (next.cgroup_id == cgroup_id) {
            uint64_t bucket_end;

            if (next.bucket > UINT64_MAX / APP_SYSCALL_BUCKET_NS) {
                errno = EOVERFLOW;
                return -1;
            }
            bucket_end = next.bucket * APP_SYSCALL_BUCKET_NS + APP_SYSCALL_BUCKET_NS;
            /* Conservative: only count a bin that ended strictly before the
             * boundary, matching the "definite" semantics already used by
             * read_app_boundary_counts for the continuous-poll boundary
             * check -- never over-count syscalls as "before" the boundary. */
            if (bucket_end <= before_boottime_ns) {
                if (bpf_map_lookup(bin_fd, &next, &value) != 0)
                    return -1;
                *out_count += value;
            }
        }
        current = next;
        have_current = true;
        steps++;
    }
    if (steps == max_steps) {
        errno = ELOOP;
        return -1;
    }
    return 0;
}

// Counts distinct (cgroup_id, syscall_nr) pairs in app_sc_first_seen whose
// recorded first-occurrence timestamp is strictly before before_boottime_ns
// -- i.e. how many different syscall *types* had already appeared at least
// once by that cutoff, as opposed to count_bins_before's raw occurrence
// count. Same enumeration shape as count_bins_before, over the first-seen
// map instead of the per-bucket map.
static int count_distinct_syscalls_before(int first_seen_fd,
                                          const struct bpf_map_info *first_seen_info,
                                          uint64_t cgroup_id,
                                          uint64_t before_boottime_ns,
                                          uint64_t *out_count)
{
    struct app_syscall_count_key current = {0, 0, 0};
    bool have_current = false;
    size_t steps = 0;
    size_t max_steps = (size_t)first_seen_info->max_entries * 2 + 16;

    *out_count = 0;
    while (steps < max_steps) {
        struct app_syscall_count_key next;
        uint64_t first_ns = 0;

        if (bpf_map_get_next_key(first_seen_fd,
                                 have_current ? (const void *)&current : NULL,
                                 &next) != 0) {
            if (errno == ENOENT)
                break;
            return -1;
        }
        if (next.cgroup_id == cgroup_id) {
            if (bpf_map_lookup(first_seen_fd, &next, &first_ns) != 0)
                return -1;
            if (first_ns < before_boottime_ns)
                (*out_count)++;
        }
        current = next;
        have_current = true;
        steps++;
    }
    if (steps == max_steps) {
        errno = ELOOP;
        return -1;
    }
    return 0;
}

// Distinct-syscall-type counterpart to read_app_boundary_counts: definite is
// how many different syscall numbers had already been seen at least once
// strictly before lower_boottime_ns (the last-known-absent bound), possible
// extends that to upper_boottime_ns (the first-known-present bound) --
// same [lower, upper] bracket semantics as the raw occurrence counts, just
// applied to app_sc_first_seen instead of app_sc_bins.
static int read_app_distinct_counts(int first_seen_fd,
                                    const struct bpf_map_info *first_seen_info,
                                    uint64_t cgroup_id,
                                    uint64_t lower_boottime_ns,
                                    uint64_t upper_boottime_ns,
                                    struct app_boundary_counts *counts)
{
    struct app_syscall_count_key current = {0, 0, 0};
    bool have_current = false;
    size_t steps = 0;
    size_t max_steps = (size_t)first_seen_info->max_entries * 2 + 16;

    while (steps < max_steps) {
        struct app_syscall_count_key next;
        uint64_t first_ns = 0;

        if (bpf_map_get_next_key(first_seen_fd,
                                 have_current ? (const void *)&current : NULL,
                                 &next) != 0) {
            if (errno == ENOENT)
                break;
            return -1;
        }
        if (next.cgroup_id == cgroup_id) {
            if (bpf_map_lookup(first_seen_fd, &next, &first_ns) != 0)
                return -1;
            if (first_ns < lower_boottime_ns)
                counts->distinct_definite++;
            if (first_ns < upper_boottime_ns)
                counts->distinct_possible++;
        }
        current = next;
        have_current = true;
        steps++;
    }
    if (steps == max_steps) {
        errno = ELOOP;
        return -1;
    }
    return 0;
}

static int emit_app_syscalls(const struct options *options, int bin_fd,
                             int count_fd, int meta_fd, int first_seen_fd,
                             const struct bpf_map_info *bin_info,
                             const struct bpf_map_info *count_info,
                             const struct bpf_map_info *meta_info,
                             const struct bpf_map_info *first_seen_info)
{
    struct app_syscall_meta_value meta = {0, 0, 0, 0, 0};
    struct app_syscall_count_key current = {0, 0, 0};
    bool have_current = false;
    bool have_meta = false;
    bool first = true;
    uint64_t histogram_total = 0;
    size_t steps = 0;
    size_t max_steps = (size_t)count_info->max_entries * 2 + 16;
    struct timestamp ts;

    if (read_timestamp(&ts) != 0)
        return -1;

    printf("{\"schema_version\":1,\"event\":\"application_syscall_snapshot\","
           "\"cgroup_id\":%" PRIu64 ",\"syscalls\":[", options->cgroup_id);

    while (steps < max_steps) {
        struct app_syscall_count_key next;
        uint64_t value = 0;

        if (bpf_map_get_next_key(count_fd,
                                 have_current ? (const void *)&current : NULL,
                                 &next) != 0) {
            if (errno == ENOENT)
                break;
            return -1;
        }
        if (next.cgroup_id == options->cgroup_id) {
            if (bpf_map_lookup(count_fd, &next, &value) != 0)
                return -1;
            printf("%s{\"nr\":%" PRIu32 ",\"count\":%" PRIu64 "}",
                   first ? "" : ",", next.syscall_nr, value);
            first = false;
            histogram_total += value;
        }
        current = next;
        have_current = true;
        steps++;
    }
    if (steps == max_steps) {
        errno = ELOOP;
        return -1;
    }

    // Read app_sc_meta only after the per-syscall counts have been fully
    // enumerated, not before: meta.total is a single atomically-incremented
    // counter, so reading it last guarantees total >= histogram_total even
    // if a handful of syscalls land while this function is running (never
    // the reverse, which would make a live process look under-counted).
    if (bpf_map_lookup(meta_fd, &options->cgroup_id, &meta) == 0)
        have_meta = true;
    else if (errno != ENOENT)
        return -1;

    printf("],\"histogram_total\":%" PRIu64 ","
           "\"bin_map_id\":%" PRIu32 ",\"count_map_id\":%" PRIu32 ","
           "\"meta_map_id\":%" PRIu32 ",\"bucket_ns\":%" PRIu64 ","
           "\"observed_realtime_ns\":%" PRIu64 ","
           "\"observed_boottime_ns\":%" PRIu64 ",\"cleanup\":%s,"
           "\"counter_present\":%s,\"total\":%" PRIu64 ","
           "\"root_tgid\":%" PRIu32 ",\"first_boottime_ns\":",
           histogram_total, bin_info->id, count_info->id, meta_info->id,
           APP_SYSCALL_BUCKET_NS, ts.realtime_ns, ts.boottime_ns,
           options->cleanup_app_syscalls ? "true" : "false",
           have_meta ? "true" : "false", meta.total, meta.root_tgid);
    if (have_meta)
        printf("%" PRIu64, meta.first_boottime_ns);
    else
        fputs("null", stdout);
    fputs(",\"last_boottime_ns\":", stdout);
    if (have_meta)
        printf("%" PRIu64, meta.last_boottime_ns);
    else
        fputs("null", stdout);
    fputc(',', stdout);

    if (options->have_before_boottime_ns) {
        uint64_t before_count = 0;
        uint64_t before_distinct_syscall_types = 0;

        if (count_bins_before(bin_fd, bin_info, options->cgroup_id,
                              options->before_boottime_ns,
                              &before_count) != 0)
            return -1;
        if (count_distinct_syscalls_before(first_seen_fd, first_seen_info,
                                           options->cgroup_id,
                                           options->before_boottime_ns,
                                           &before_distinct_syscall_types) != 0)
            return -1;
        printf("\"before_boottime_ns\":%" PRIu64 ",\"before_count\":%" PRIu64 ","
               "\"before_distinct_syscall_types\":%" PRIu64 "}\n",
               options->before_boottime_ns, before_count,
               before_distinct_syscall_types);
    } else {
        fputs("\"before_boottime_ns\":null,\"before_count\":null,"
              "\"before_distinct_syscall_types\":null}\n", stdout);
    }
    return 0;
}

static int delete_app_bins_for_cgroup(int fd,
                                      const struct bpf_map_info *info,
                                      uint64_t cgroup_id)
{
    size_t passes = 0;
    size_t max_passes = (size_t)info->max_entries + 1;

    while (passes < max_passes) {
        struct app_syscall_bin_key current = {0, 0};
        bool have_current = false;
        bool deleted = false;
        size_t steps = 0;
        size_t max_steps = (size_t)info->max_entries * 2 + 16;

        while (steps < max_steps) {
            struct app_syscall_bin_key next;
            if (bpf_map_get_next_key(fd,
                                     have_current ? (const void *)&current : NULL,
                                     &next) != 0) {
                if (errno == ENOENT)
                    break;
                return -1;
            }
            if (next.cgroup_id == cgroup_id) {
                if (bpf_map_delete(fd, &next) != 0 && errno != ENOENT)
                    return -1;
                deleted = true;
                break;
            }
            current = next;
            have_current = true;
            steps++;
        }
        if (!deleted)
            return 0;
        passes++;
    }
    errno = ELOOP;
    return -1;
}

static int delete_app_counts_for_cgroup(int fd,
                                        const struct bpf_map_info *info,
                                        uint64_t cgroup_id)
{
    size_t passes = 0;
    size_t max_passes = (size_t)info->max_entries + 1;

    while (passes < max_passes) {
        struct app_syscall_count_key current = {0, 0, 0};
        bool have_current = false;
        bool deleted = false;
        size_t steps = 0;
        size_t max_steps = (size_t)info->max_entries * 2 + 16;

        while (steps < max_steps) {
            struct app_syscall_count_key next;
            if (bpf_map_get_next_key(fd,
                                     have_current ? (const void *)&current : NULL,
                                     &next) != 0) {
                if (errno == ENOENT)
                    break;
                return -1;
            }
            if (next.cgroup_id == cgroup_id) {
                if (bpf_map_delete(fd, &next) != 0 && errno != ENOENT)
                    return -1;
                deleted = true;
                break;
            }
            current = next;
            have_current = true;
            steps++;
        }
        if (!deleted)
            return 0;
        passes++;
    }
    errno = ELOOP;
    return -1;
}

static void emit_map_snapshot(const struct options *options,
                              const struct bpf_map_info *outer_info,
                              const struct bpf_map_info *inner_info,
                              const struct key_array *keys,
                              const struct timestamp *ts)
{
    printf("{\"schema_version\":1,\"event\":\"map_snapshot\","
           "\"policy_id\":%" PRIu32 ",\"map_path\":",
           options->policy_id);
    json_string(options->map_path);
    printf(",\"outer_map_id\":%" PRIu32 ",\"inner_map_id\":%" PRIu32 ","
           "\"realtime_ns\":%" PRIu64 ",\"boottime_ns\":%" PRIu64 ","
           "\"count\":%zu,\"cgroup_ids\":",
           outer_info->id, inner_info->id, ts->realtime_ns, ts->boottime_ns,
           keys->count);
    print_key_array(keys);
    fputs("}\n", stdout);
}

static void emit_watch_ready(const struct options *options,
                             const struct bpf_map_info *outer_info,
                             const struct bpf_map_info *inner_info,
                             const struct key_array *baseline,
                             const struct timestamp *ts)
{
    printf("{\"schema_version\":1,\"event\":\"watch_ready\","
           "\"policy_id\":%" PRIu32 ",\"map_path\":",
           options->policy_id);
    json_string(options->map_path);
    printf(",\"outer_map_id\":%" PRIu32 ",\"inner_map_id\":%" PRIu32 ","
           "\"realtime_ns\":%" PRIu64 ",\"boottime_ns\":%" PRIu64 ","
           "\"poll_us\":%" PRIu64 ",\"timeout_ms\":%" PRIu64 ","
           "\"exit_after_insert\":%s,\"baseline_count\":%zu,"
           "\"baseline_cgroup_ids\":",
           outer_info->id, inner_info->id, ts->realtime_ns, ts->boottime_ns,
           options->poll_us, options->timeout_ms,
           options->exit_after_insert ? "true" : "false", baseline->count);
    print_key_array(baseline);
    fputs("}\n", stdout);
}

static void emit_map_insert(const struct options *options, uint64_t cgroup_id,
                            const struct timestamp *lower_bound,
                            const struct timestamp *upper_bound,
                            const struct app_boundary_counts *app_counts)
{
    printf("{\"schema_version\":1,\"event\":\"map_insert\","
           "\"policy_id\":%" PRIu32 ",\"cgroup_id\":%" PRIu64 ","
           "\"last_absent_realtime_ns\":%" PRIu64 ","
           "\"last_absent_boottime_ns\":%" PRIu64 ","
           "\"first_present_realtime_ns\":%" PRIu64 ","
           "\"first_present_boottime_ns\":%" PRIu64 ","
           "\"lower_bound_realtime_ns\":%" PRIu64 ","
           "\"lower_bound_boottime_ns\":%" PRIu64 ","
           "\"upper_bound_realtime_ns\":%" PRIu64 ","
           "\"upper_bound_boottime_ns\":%" PRIu64 ","
           "\"application_syscalls_uncovered_definite\":%" PRIu64 ","
           "\"application_syscalls_uncovered_possible\":%" PRIu64 ","
           "\"application_syscalls_observed_at_boundary\":%" PRIu64 ","
           "\"application_matching_time_bins\":%" PRIu64 ","
           "\"application_time_bucket_ns\":%" PRIu64 ","
           "\"application_distinct_syscall_types_uncovered_definite\":%" PRIu64 ","
           "\"application_distinct_syscall_types_uncovered_possible\":%" PRIu64 ","
           "\"bound_semantics\":\"previous_absent_enumeration_begin_to_"
           "current_present_enumeration_end\"}\n",
           options->policy_id, cgroup_id, lower_bound->realtime_ns,
           lower_bound->boottime_ns, upper_bound->realtime_ns,
           upper_bound->boottime_ns, lower_bound->realtime_ns,
           lower_bound->boottime_ns, upper_bound->realtime_ns,
           upper_bound->boottime_ns, app_counts->definite,
           app_counts->possible, app_counts->observed,
           app_counts->matching_bins, APP_SYSCALL_BUCKET_NS,
           app_counts->distinct_definite, app_counts->distinct_possible);
}

static void emit_timeout(const struct options *options,
                         const struct timestamp *ts, uint64_t insert_count)
{
    printf("{\"schema_version\":1,\"event\":\"timeout\","
           "\"policy_id\":%" PRIu32 ",\"realtime_ns\":%" PRIu64 ","
           "\"boottime_ns\":%" PRIu64 ",\"insert_count\":%" PRIu64 "}\n",
           options->policy_id, ts->realtime_ns, ts->boottime_ns, insert_count);
}

int main(int argc, char **argv)
{
    struct options options;
    struct bpf_map_info outer_info;
    struct bpf_map_info inner_info;
    struct key_array baseline;
    struct timestamp previous_snapshot;
    struct u64_set seen;
    uint32_t inner_map_id;
    int outer_fd = -1;
    int inner_fd = -1;
    int app_bin_fd = -1;
    int app_count_fd = -1;
    int app_meta_fd = -1;
    int app_first_seen_fd = -1;
    struct bpf_map_info app_bin_info;
    struct bpf_map_info app_count_info;
    struct bpf_map_info app_meta_info;
    struct bpf_map_info app_first_seen_info;
    int saved_errno;
    size_t i;
    int exit_code = 1;

    memset(&baseline, 0, sizeof(baseline));
    memset(&seen, 0, sizeof(seen));

    if (parse_options(argc, argv, &options) != 0) {
        usage(stderr, argv[0]);
        return 2;
    }

    if (setvbuf(stdout, NULL, _IOLBF, 0) != 0) {
        perror("setvbuf");
        return 1;
    }

    if (options.lookup_app_syscalls) {
        app_bin_fd = bpf_obj_get(options.app_bin_map_path);
        app_count_fd = bpf_obj_get(options.app_count_map_path);
        app_meta_fd = bpf_obj_get(options.app_meta_map_path);
        app_first_seen_fd = bpf_obj_get(options.app_first_seen_map_path);
        if (app_bin_fd < 0 || app_count_fd < 0 || app_meta_fd < 0 ||
            app_first_seen_fd < 0) {
            emit_error("open_application_syscall_maps", errno);
            goto out;
        }
        if (bpf_map_get_info(app_bin_fd, &app_bin_info) != 0 ||
            bpf_map_get_info(app_count_fd, &app_count_info) != 0 ||
            bpf_map_get_info(app_meta_fd, &app_meta_info) != 0 ||
            bpf_map_get_info(app_first_seen_fd, &app_first_seen_info) != 0) {
            emit_error("inspect_application_syscall_maps", errno);
            goto out;
        }
        if (app_bin_info.type != BPF_MAP_TYPE_HASH ||
            app_bin_info.key_size != sizeof(struct app_syscall_bin_key) ||
            app_bin_info.value_size != sizeof(uint64_t) ||
            app_count_info.type != BPF_MAP_TYPE_HASH ||
            app_count_info.key_size != sizeof(struct app_syscall_count_key) ||
            app_count_info.value_size != sizeof(uint64_t) ||
            app_meta_info.type != BPF_MAP_TYPE_HASH ||
            app_meta_info.key_size != sizeof(uint64_t) ||
            app_meta_info.value_size != sizeof(struct app_syscall_meta_value) ||
            app_first_seen_info.type != BPF_MAP_TYPE_HASH ||
            app_first_seen_info.key_size != sizeof(struct app_syscall_count_key) ||
            app_first_seen_info.value_size != sizeof(uint64_t)) {
            emit_error("validate_application_syscall_maps", EINVAL);
            goto out;
        }
        if (emit_app_syscalls(&options, app_bin_fd, app_count_fd, app_meta_fd,
                              app_first_seen_fd, &app_bin_info,
                              &app_count_info, &app_meta_info,
                              &app_first_seen_info) != 0) {
            emit_error("lookup_application_syscalls", errno);
            goto out;
        }
        if (options.cleanup_app_syscalls) {
            if (delete_app_bins_for_cgroup(app_bin_fd, &app_bin_info,
                                           options.cgroup_id) != 0 ||
                delete_app_counts_for_cgroup(app_count_fd, &app_count_info,
                                             options.cgroup_id) != 0 ||
                delete_app_counts_for_cgroup(app_first_seen_fd,
                                             &app_first_seen_info,
                                             options.cgroup_id) != 0 ||
                (bpf_map_delete(app_meta_fd, &options.cgroup_id) != 0 &&
                 errno != ENOENT)) {
                emit_error("cleanup_application_syscalls", errno);
                goto out;
            }
        }
        exit_code = 0;
        goto out;
    }

    outer_fd = bpf_obj_get(options.map_path);
    if (outer_fd < 0) {
        emit_error("open_outer_map", errno);
        goto out;
    }
    if (bpf_map_get_info(outer_fd, &outer_info) != 0) {
        emit_error("inspect_outer_map", errno);
        goto out;
    }
    if (options.inspect_map) {
        if (read_timestamp(&previous_snapshot) != 0) {
            emit_error("timestamp_map_info", errno);
            goto out;
        }
        emit_map_info(&options, &outer_info, &previous_snapshot);
        exit_code = 0;
        goto out;
    }
    if (options.lookup_ns_value) {
        struct {
            uint32_t mnt_ns;
            uint32_t pid_ns;
        } key = {options.mnt_ns, options.pid_ns};
        uint64_t value = 0;

        if (outer_info.type != BPF_MAP_TYPE_HASH ||
            outer_info.key_size != sizeof(key) ||
            outer_info.value_size != sizeof(value)) {
            emit_error("validate_ns_map", EINVAL);
            goto out;
        }
        if (bpf_map_lookup(outer_fd, &key, &value) != 0) {
            emit_error("lookup_ns_value", errno);
            goto out;
        }
        if (read_timestamp(&previous_snapshot) != 0) {
            emit_error("timestamp_ns_value", errno);
            goto out;
        }
        emit_ns_value(&options, value, &outer_info, &previous_snapshot);
        exit_code = 0;
        goto out;
    }
    if (options.lookup_sygma_misses) {
        if (outer_info.type != BPF_MAP_TYPE_HASH ||
            outer_info.key_size != sizeof(struct sygma_miss_key) ||
            outer_info.value_size != sizeof(uint32_t)) {
            emit_error("validate_sygma_miss_map", EINVAL);
            goto out;
        }
        if (emit_sygma_misses(&options, outer_fd, &outer_info) != 0) {
            emit_error("lookup_sygma_misses", errno);
            goto out;
        }
        exit_code = 0;
        goto out;
    }
    if (outer_info.type != BPF_MAP_TYPE_HASH_OF_MAPS ||
        outer_info.key_size != sizeof(uint32_t) ||
        outer_info.value_size != sizeof(uint32_t)) {
        emit_error("validate_outer_map", EINVAL);
        goto out;
    }

    if (bpf_map_lookup(outer_fd, &options.policy_id, &inner_map_id) != 0) {
        emit_error("lookup_policy_id", errno);
        goto out;
    }
    inner_fd = bpf_map_get_fd_by_id(inner_map_id);
    if (inner_fd < 0) {
        emit_error("open_inner_map", errno);
        goto out;
    }
    if (bpf_map_get_info(inner_fd, &inner_info) != 0) {
        emit_error("inspect_inner_map", errno);
        goto out;
    }
    if (inner_info.type != BPF_MAP_TYPE_HASH ||
        inner_info.key_size != sizeof(uint64_t) || inner_info.value_size != 1) {
        emit_error("validate_inner_map", EINVAL);
        goto out;
    }

    if (enumerate_keys(inner_fd, inner_info.max_entries, &baseline) != 0) {
        emit_error("enumerate_baseline", errno);
        goto out;
    }
    if (read_timestamp(&previous_snapshot) != 0) {
        emit_error("timestamp_baseline", errno);
        goto out;
    }

    if (options.once) {
        /* --once never reads the application syscall bin map (no per-key
         * insert-boundary evidence is produced), so it must not require
         * app_sc_bins to be pinned. Only the continuous-poll loop below
         * needs it. */
        emit_map_snapshot(&options, &outer_info, &inner_info, &baseline,
                          &previous_snapshot);
        exit_code = 0;
        goto out;
    }

    app_bin_fd = bpf_obj_get(options.app_bin_map_path);
    app_first_seen_fd = bpf_obj_get(options.app_first_seen_map_path);
    if (app_bin_fd < 0 || app_first_seen_fd < 0) {
        emit_error("open_application_syscall_bin_map", errno);
        goto out;
    }
    if (bpf_map_get_info(app_bin_fd, &app_bin_info) != 0 ||
        bpf_map_get_info(app_first_seen_fd, &app_first_seen_info) != 0) {
        emit_error("inspect_application_syscall_bin_map", errno);
        goto out;
    }
    if (app_bin_info.type != BPF_MAP_TYPE_HASH ||
        app_bin_info.key_size != sizeof(struct app_syscall_bin_key) ||
        app_bin_info.value_size != sizeof(uint64_t) ||
        app_first_seen_info.type != BPF_MAP_TYPE_HASH ||
        app_first_seen_info.key_size != sizeof(struct app_syscall_count_key) ||
        app_first_seen_info.value_size != sizeof(uint64_t)) {
        emit_error("validate_application_syscall_bin_map", EINVAL);
        goto out;
    }

    if (set_init(&seen, baseline.count + 16) != 0) {
        emit_error("allocate_seen_set", errno);
        goto out;
    }
    for (i = 0; i < baseline.count; i++) {
        if (set_add(&seen, baseline.items[i]) < 0) {
            emit_error("initialize_seen_set", errno);
            goto out;
        }
    }

    emit_watch_ready(&options, &outer_info, &inner_info, &baseline,
                     &previous_snapshot);

    {
        uint64_t poll_ns = options.poll_us * NS_PER_US;
        uint64_t deadline_ns = previous_snapshot.boottime_ns +
                               options.timeout_ms * NS_PER_MS;
        uint64_t next_poll_ns = previous_snapshot.boottime_ns + poll_ns;
        uint64_t insert_count = 0;

        for (;;) {
            struct key_array current;
            struct timestamp poll_begin;
            struct timestamp poll_end;

            if (next_poll_ns > deadline_ns)
                next_poll_ns = deadline_ns;
            if (sleep_until_boottime(next_poll_ns) != 0) {
                emit_error("poll_wait", errno);
                goto out;
            }

            if (read_timestamp(&poll_begin) != 0) {
                emit_error("timestamp_poll_begin", errno);
                goto out;
            }
            if (enumerate_keys(inner_fd, inner_info.max_entries, &current) != 0) {
                emit_error("enumerate_poll", errno);
                goto out;
            }
            if (read_timestamp(&poll_end) != 0) {
                saved_errno = errno;
                free_key_array(&current);
                emit_error("timestamp_poll_end", saved_errno);
                goto out;
            }

            for (i = 0; i < current.count; i++) {
                int added = set_add(&seen, current.items[i]);

                if (added < 0) {
                    saved_errno = errno;
                    free_key_array(&current);
                    emit_error("update_seen_set", saved_errno);
                    goto out;
                }
                if (added == 1) {
                    struct app_boundary_counts app_counts;

                    if (read_app_boundary_counts(
                            app_bin_fd, &app_bin_info, current.items[i],
                            previous_snapshot.boottime_ns,
                            poll_end.boottime_ns, &app_counts) != 0) {
                        saved_errno = errno;
                        free_key_array(&current);
                        emit_error("read_application_boundary_counts",
                                   saved_errno);
                        goto out;
                    }
                    if (read_app_distinct_counts(
                            app_first_seen_fd, &app_first_seen_info,
                            current.items[i], previous_snapshot.boottime_ns,
                            poll_end.boottime_ns, &app_counts) != 0) {
                        saved_errno = errno;
                        free_key_array(&current);
                        emit_error("read_application_distinct_counts",
                                   saved_errno);
                        goto out;
                    }
                    emit_map_insert(&options, current.items[i],
                                    &previous_snapshot, &poll_end,
                                    &app_counts);
                    insert_count++;
                    if (options.exit_after_insert) {
                        free_key_array(&current);
                        exit_code = 0;
                        goto out;
                    }
                }
            }
            free_key_array(&current);
            /*
             * A key absent from this enumeration cannot have existed before
             * poll_begin (target keys are monotonic until Pod deletion).  It
             * may, however, have been inserted during enumeration and missed
             * by GET_NEXT_KEY, so poll_end is not a valid absence lower bound.
             */
            previous_snapshot = poll_begin;

            if (poll_end.boottime_ns >= deadline_ns) {
                emit_timeout(&options, &poll_end, insert_count);
                /* A timeout is a measured outcome, not a watcher failure. */
                exit_code = 0;
                goto out;
            }

            next_poll_ns += poll_ns;
            if (next_poll_ns <= poll_end.boottime_ns) {
                uint64_t missed =
                    (poll_end.boottime_ns - next_poll_ns) / poll_ns + 1;
                next_poll_ns += missed * poll_ns;
            }
        }
    }

out:
    free_key_array(&baseline);
    set_free(&seen);
    if (inner_fd >= 0)
        close(inner_fd);
    if (outer_fd >= 0)
        close(outer_fd);
    if (app_bin_fd >= 0)
        close(app_bin_fd);
    if (app_count_fd >= 0)
        close(app_count_fd);
    if (app_meta_fd >= 0)
        close(app_meta_fd);
    if (app_first_seen_fd >= 0)
        close(app_first_seen_fd);
    return exit_code;
}

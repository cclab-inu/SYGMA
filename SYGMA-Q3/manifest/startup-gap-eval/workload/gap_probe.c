// SPDX-License-Identifier: Apache-2.0
// A dependency-free PID-1 application launcher for startup-gap evaluation.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if !defined(__x86_64__)
#error "gap_probe supports x86-64 only"
#endif

#ifndef SYS_name_to_handle_at
#define SYS_name_to_handle_at 303
#endif

#define DEFAULT_INTERVAL_US UINT64_C(1000)
#define DEFAULT_DURATION_MS UINT64_C(5000)
#define DEFAULT_EVIDENCE_HOLD_MS UINT64_C(5000)
#define MAX_INTERVAL_US UINT64_C(60000000)
#define MAX_DURATION_MS UINT64_C(86400000)
#define NS_PER_US UINT64_C(1000)
#define NS_PER_MS UINT64_C(1000000)
#define APP_LOG_PATH "/tmp/startup-gap-app.log"
// Distroless bases (e.g. Online Boutique's Go services) ship no /tmp at
// all, so opening APP_LOG_PATH fails closed with ENOENT before the real
// application is ever spawned. /opt/gap always exists in every carrier
// image -- it is where this launcher itself was COPY'd -- so it is a safe
// fallback that needs no extra image layer.
#define APP_LOG_FALLBACK_PATH "/opt/gap/startup-gap-app.log"
#define APP_TERM_GRACE_MS UINT64_C(2000)
#define APP_KILL_GRACE_MS UINT64_C(2000)
#define APP_POLL_MS UINT64_C(10)

struct timestamp {
    uint64_t realtime_ns;
    uint64_t boottime_ns;
};

struct application {
    const char *name;
    char **argv;
    pid_t pid;
    pid_t pgid;
    int wait_status;
    bool reaped;
    bool exit_event_emitted;
};

static volatile sig_atomic_t termination_requested;
static const char *g_app_log_path = APP_LOG_PATH;
static volatile sig_atomic_t child_state_changed;

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

static uint64_t read_boottime_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_BOOTTIME, &ts) != 0) {
        perror("clock_gettime(CLOCK_BOOTTIME)");
        exit(1);
    }
    return timespec_to_ns(&ts);
}

static void termination_signal_handler(int signal_number)
{
    (void)signal_number;
    termination_requested = 1;
}

static void child_signal_handler(int signal_number)
{
    (void)signal_number;
    child_state_changed = 1;
}

static int install_application_signal_handlers(void)
{
    static const int termination_signals[] = {SIGTERM, SIGINT, SIGHUP};
    struct sigaction action;
    size_t i;

    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_handler = termination_signal_handler;
    for (i = 0; i < sizeof(termination_signals) /
                        sizeof(termination_signals[0]);
         i++) {
        if (sigaction(termination_signals[i], &action, NULL) != 0)
            return -1;
    }

    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_handler = child_signal_handler;
    action.sa_flags = SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &action, NULL) != 0)
        return -1;

    return 0;
}

static void print_json_string(const char *value)
{
    const unsigned char *cursor = (const unsigned char *)value;

    putchar('"');
    while (*cursor != '\0') {
        unsigned char byte = *cursor++;

        switch (byte) {
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
            if (byte < 0x20 || byte >= 0x7f)
                printf("\\u%04x", (unsigned int)byte);
            else
                putchar((int)byte);
            break;
        }
    }
    putchar('"');
}

static void child_write_error(const char *message)
{
    size_t remaining = strlen(message);
    const char *cursor = message;

    while (remaining > 0) {
        ssize_t written = write(STDERR_FILENO, cursor, remaining);

        if (written > 0) {
            cursor += written;
            remaining -= (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR)
            continue;
        break;
    }
}

static int emit_application_spawn(const struct application *application)
{
    struct timestamp timestamp;

    if (read_timestamp(&timestamp) != 0)
        return -1;

    fputs("{\"schema_version\":2,\"event\":\"app_spawn\","
          "\"application\":",
          stdout);
    print_json_string(application->name);
    printf(",\"pid\":%ld,\"pgid\":%ld,\"realtime_ns\":%" PRIu64
           ",\"boottime_ns\":%" PRIu64 ",\"command\":",
           (long)application->pid, (long)application->pgid,
           timestamp.realtime_ns, timestamp.boottime_ns);
    print_json_string(application->argv[0]);
    fputs(",\"log_path\":", stdout);
    print_json_string(g_app_log_path);
    fputs("}\n", stdout);
    return ferror(stdout) ? -1 : 0;
}

static int emit_application_exit(struct application *application,
                                 const char *phase)
{
    struct timestamp timestamp;
    int exit_code = -1;
    int term_signal = 0;
    bool core_dumped = false;

    if (application->exit_event_emitted)
        return 0;
    if (read_timestamp(&timestamp) != 0)
        return -1;

    if (WIFEXITED(application->wait_status))
        exit_code = WEXITSTATUS(application->wait_status);
    if (WIFSIGNALED(application->wait_status)) {
        term_signal = WTERMSIG(application->wait_status);
#ifdef WCOREDUMP
        core_dumped = WCOREDUMP(application->wait_status) != 0;
#endif
    }

    fputs("{\"schema_version\":2,\"event\":\"app_exit\","
          "\"application\":",
          stdout);
    print_json_string(application->name);
    printf(",\"pid\":%ld,\"pgid\":%ld,\"realtime_ns\":%" PRIu64
           ",\"boottime_ns\":%" PRIu64 ",\"phase\":",
           (long)application->pid, (long)application->pgid,
           timestamp.realtime_ns, timestamp.boottime_ns);
    print_json_string(phase);
    printf(",\"status_known\":true,\"status_raw\":%d,"
           "\"exit_code\":%d,\"term_signal\":%d,"
           "\"core_dumped\":%s}\n",
           application->wait_status, exit_code, term_signal,
           core_dumped ? "true" : "false");
    application->exit_event_emitted = true;
    return ferror(stdout) ? -1 : 0;
}

static int emit_unknown_application_exit(struct application *application,
                                         const char *phase)
{
    struct timestamp timestamp;

    if (application->exit_event_emitted)
        return 0;
    if (read_timestamp(&timestamp) != 0)
        return -1;

    fputs("{\"schema_version\":2,\"event\":\"app_exit\","
          "\"application\":",
          stdout);
    print_json_string(application->name);
    printf(",\"pid\":%ld,\"pgid\":%ld,\"realtime_ns\":%" PRIu64
           ",\"boottime_ns\":%" PRIu64 ",\"phase\":",
           (long)application->pid, (long)application->pgid,
           timestamp.realtime_ns, timestamp.boottime_ns);
    print_json_string(phase);
    fputs(",\"status_known\":false,\"status_raw\":-1,"
          "\"exit_code\":-1,\"term_signal\":0,"
          "\"core_dumped\":false}\n",
          stdout);
    application->exit_event_emitted = true;
    return ferror(stdout) ? -1 : 0;
}

/* Return 1 after reaping the application, 0 while it is alive, or -1. */
static int poll_application(struct application *application,
                            const char *phase)
{
    pid_t waited;

    if (application->reaped)
        return 1;

    do {
        waited = waitpid(application->pid, &application->wait_status,
                         WNOHANG);
    } while (waited < 0 && errno == EINTR);

    if (waited == 0)
        return 0;
    if (waited == application->pid) {
        application->reaped = true;
        if (emit_application_exit(application, phase) != 0)
            return -1;
        return 1;
    }

    return -1;
}

static int spawn_application(struct application *application)
{
    int log_fd;
    pid_t child;
    int saved_errno;

    log_fd = open(APP_LOG_PATH, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                  0644);
    if (log_fd < 0 && errno == ENOENT) {
        log_fd = open(APP_LOG_FALLBACK_PATH,
                      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (log_fd >= 0)
            g_app_log_path = APP_LOG_FALLBACK_PATH;
    }
    if (log_fd < 0)
        return -1;

    child = fork();
    if (child < 0) {
        saved_errno = errno;
        close(log_fd);
        errno = saved_errno;
        return -1;
    }

    if (child == 0) {
        if (dup2(log_fd, STDOUT_FILENO) < 0 ||
            dup2(log_fd, STDERR_FILENO) < 0) {
            child_write_error("gap-probe: application log redirect failed\n");
            _exit(126);
        }
        if (log_fd != STDOUT_FILENO && log_fd != STDERR_FILENO)
            close(log_fd);
        if (setpgid(0, 0) != 0) {
            child_write_error("gap-probe: setpgid failed\n");
            _exit(126);
        }
        execvp(application->argv[0], application->argv);
        saved_errno = errno;
        child_write_error("gap-probe: application exec failed\n");
        _exit(saved_errno == ENOENT ? 127 : 126);
    }

    close(log_fd);
    application->pid = child;
    application->pgid = child;

    if (setpgid(child, child) != 0 && errno != EACCES && errno != ESRCH) {
        saved_errno = errno;
        kill(child, SIGKILL);
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR)
            ;
        errno = saved_errno;
        return -1;
    }

    if (emit_application_spawn(application) != 0)
        return -1;
    return 0;
}

static bool application_group_exists(const struct application *application)
{
    if (kill(-application->pgid, 0) == 0)
        return true;
    return errno == EPERM;
}

static void reap_adopted_children(const struct application *application)
{
    int status;

    if (!application->reaped)
        return;
    while (waitpid(-1, &status, WNOHANG) > 0)
        ;
}

static int sleep_for_poll_interval(uint64_t remaining_ns)
{
    uint64_t sleep_ns = APP_POLL_MS * NS_PER_MS;
    struct timespec request;

    if (remaining_ns < sleep_ns)
        sleep_ns = remaining_ns;
    request.tv_sec = (time_t)(sleep_ns / UINT64_C(1000000000));
    request.tv_nsec = (long)(sleep_ns % UINT64_C(1000000000));
    while (nanosleep(&request, &request) != 0) {
        if (errno != EINTR)
            return -1;
        if (termination_requested || child_state_changed)
            break;
    }
    return 0;
}

static int wait_for_application_group(struct application *application,
                                      uint64_t timeout_ms,
                                      const char *phase)
{
    uint64_t deadline_ns = read_boottime_ns() + timeout_ms * NS_PER_MS;

    for (;;) {
        uint64_t now_ns;
        int poll_result;

        child_state_changed = 0;
        poll_result = poll_application(application, phase);
        if (poll_result < 0)
            return -1;
        reap_adopted_children(application);
        if (application->reaped && !application_group_exists(application))
            return 0;

        now_ns = read_boottime_ns();
        if (now_ns >= deadline_ns)
            return 1;
        if (sleep_for_poll_interval(deadline_ns - now_ns) != 0)
            return -1;
    }
}

static int terminate_application(struct application *application)
{
    int result;
    bool group_exists = application_group_exists(application);

    if (group_exists && kill(-application->pgid, SIGTERM) != 0 &&
        errno != ESRCH)
        return -1;
    if (!application->reaped && kill(application->pid, SIGTERM) != 0 &&
        errno != ESRCH)
        return -1;

    result = wait_for_application_group(application, APP_TERM_GRACE_MS,
                                        "cleanup");
    if (result < 0)
        return -1;
    if (result == 0)
        return 0;

    group_exists = application_group_exists(application);
    if (group_exists && kill(-application->pgid, SIGKILL) != 0 &&
        errno != ESRCH)
        return -1;
    if (!application->reaped && kill(application->pid, SIGKILL) != 0 &&
        errno != ESRCH)
        return -1;

    result = wait_for_application_group(application, APP_KILL_GRACE_MS,
                                        "cleanup");
    if (result != 0) {
        if (!application->exit_event_emitted)
            emit_unknown_application_exit(application, "cleanup");
        errno = result < 0 ? errno : ETIMEDOUT;
        return -1;
    }
    return 0;
}

static int hold_application_evidence(struct application *application,
                                     uint64_t evidence_hold_ms)
{
    uint64_t deadline_ns = read_boottime_ns() +
                           evidence_hold_ms * NS_PER_MS;

    for (;;) {
        uint64_t now_ns;

        if (termination_requested)
            return 1;
        if (child_state_changed && !application->reaped) {
            int poll_result;

            child_state_changed = 0;
            poll_result = poll_application(application, "evidence_hold");
            if (poll_result < 0)
                return -1;
        }

        now_ns = read_boottime_ns();
        if (now_ns >= deadline_ns)
            break;
        if (sleep_for_poll_interval(deadline_ns - now_ns) != 0)
            return -1;
    }

    if (!application->reaped &&
        poll_application(application, "evidence_hold") < 0)
        return -1;
    return 0;
}

/*
 * Invoke the one-argument x86-64 syscall instruction directly so libc cannot
 * add any unrelated calls around the observation marker.
 */
/*
 * Tetragon obtains policy-filter keys from name_to_handle_at(2) and decodes
 * the first eight handle bytes as a little-endian cgroup ID. Resolve the same
 * value only after the timed attempt loop, so correlation cannot give the
 * asynchronous arm extra time before the first measured call.
 */
static int read_cgroup_id(uint64_t *cgroup_id)
{
    struct {
        unsigned int handle_bytes;
        int handle_type;
        unsigned char bytes[8];
    } handle = {0};
    char cgroup_path[PATH_MAX];
    char line[PATH_MAX];
    FILE *stream;
    int mount_id = 0;
    long rc;

    stream = fopen("/proc/self/cgroup", "r");
    if (stream == NULL)
        return -1;
    cgroup_path[0] = '\0';
    while (fgets(line, sizeof(line), stream) != NULL) {
        char *relative;
        size_t length;

        if (strncmp(line, "0::", 3) != 0)
            continue;
        relative = line + 3;
        length = strcspn(relative, "\r\n");
        relative[length] = '\0';
        if (snprintf(cgroup_path, sizeof(cgroup_path), "/sys/fs/cgroup%s",
                     strcmp(relative, "/") == 0 ? "" : relative) >=
            (int)sizeof(cgroup_path)) {
            fclose(stream);
            errno = ENAMETOOLONG;
            return -1;
        }
        break;
    }
    if (fclose(stream) != 0)
        return -1;
    if (cgroup_path[0] == '\0') {
        errno = ENOENT;
        return -1;
    }

    handle.handle_bytes = sizeof(handle.bytes);
    rc = syscall(SYS_name_to_handle_at, AT_FDCWD, cgroup_path,
                 &handle, &mount_id, 0);
    if (rc != 0)
        return -1;
    if (handle.handle_bytes < sizeof(*cgroup_id)) {
        errno = EPROTO;
        return -1;
    }

    memcpy(cgroup_id, handle.bytes, sizeof(*cgroup_id));
    return 0;
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
            "Usage: %s [--interval-us N] [--duration-ms N] "
            "[--evidence-hold-ms N] "
            "[--application NAME -- COMMAND [ARGS...]]\n"
            "Environment: INTERVAL_US (default 1000), "
            "DURATION_MS (default 5000), EVIDENCE_HOLD_MS (default 5000)\n",
            program);
}

static int load_environment(uint64_t *interval_us, uint64_t *duration_ms,
                            uint64_t *evidence_hold_ms)
{
    const char *value;

    value = getenv("INTERVAL_US");
    if (value != NULL &&
        parse_u64(value, 1, MAX_INTERVAL_US, interval_us) != 0) {
        fprintf(stderr, "invalid INTERVAL_US: %s\n", value);
        return -1;
    }

    value = getenv("DURATION_MS");
    if (value != NULL &&
        parse_u64(value, 1, MAX_DURATION_MS, duration_ms) != 0) {
        fprintf(stderr, "invalid DURATION_MS: %s\n", value);
        return -1;
    }

    value = getenv("EVIDENCE_HOLD_MS");
    if (value != NULL &&
        parse_u64(value, 1, MAX_DURATION_MS, evidence_hold_ms) != 0) {
        fprintf(stderr, "invalid EVIDENCE_HOLD_MS: %s\n", value);
        return -1;
    }

    return 0;
}

static int parse_arguments(int argc, char **argv, uint64_t *interval_us,
                           uint64_t *duration_ms, uint64_t *evidence_hold_ms,
                           struct application *application)
{
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(stdout, argv[0]);
            exit(0);
        }

        if (strcmp(argv[i], "--interval-us") == 0) {
            if (++i >= argc ||
                parse_u64(argv[i], 1, MAX_INTERVAL_US, interval_us) != 0) {
                fprintf(stderr, "invalid --interval-us value\n");
                return -1;
            }
            continue;
        }

        if (strcmp(argv[i], "--duration-ms") == 0) {
            if (++i >= argc ||
                parse_u64(argv[i], 1, MAX_DURATION_MS, duration_ms) != 0) {
                fprintf(stderr, "invalid --duration-ms value\n");
                return -1;
            }
            continue;
        }

        if (strcmp(argv[i], "--evidence-hold-ms") == 0) {
            if (++i >= argc ||
                parse_u64(argv[i], 1, MAX_DURATION_MS,
                          evidence_hold_ms) != 0) {
                fprintf(stderr, "invalid --evidence-hold-ms value\n");
                return -1;
            }
            continue;
        }

        if (strcmp(argv[i], "--application") == 0) {
            if (++i >= argc || argv[i][0] == '\0') {
                fprintf(stderr, "invalid --application name\n");
                return -1;
            }
            application->name = argv[i];
            if (++i >= argc || strcmp(argv[i], "--") != 0) {
                fprintf(stderr,
                        "--application requires -- before the command\n");
                return -1;
            }
            if (++i >= argc || argv[i][0] == '\0') {
                fprintf(stderr, "--application command is missing\n");
                return -1;
            }
            application->argv = &argv[i];
            return 0;
        }

        fprintf(stderr, "unknown argument: %s\n", argv[i]);
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    uint64_t interval_us = DEFAULT_INTERVAL_US;
    uint64_t duration_ms = DEFAULT_DURATION_MS;
    uint64_t evidence_hold_ms = DEFAULT_EVIDENCE_HOLD_MS;
    uint64_t interval_ns;
    uint64_t deadline_ns;
    uint64_t next_poll_ns;
    uint64_t cgroup_id = 0;
    int cgroup_id_errno = 0;
    int final_status = 0;
    bool application_exited_during_measurement = false;
    bool measurement_interrupted = false;
    bool measurement_internal_error = false;
    bool application_alive_at_summary = false;
    struct application application = {0};
    struct timestamp start;
    struct timestamp end;

    if (load_environment(&interval_us, &duration_ms, &evidence_hold_ms) != 0 ||
        parse_arguments(argc, argv, &interval_us, &duration_ms,
                        &evidence_hold_ms, &application) != 0) {
        usage(stderr, argv[0]);
        return 2;
    }

    /* Make each JSON object observable as soon as it is recorded. */
    if (setvbuf(stdout, NULL, _IOLBF, 0) != 0) {
        perror("setvbuf");
        return 1;
    }

    if (application.name != NULL &&
        install_application_signal_handlers() != 0) {
        perror("sigaction(application launcher)");
        return 1;
    }

    if (read_timestamp(&start) != 0) {
        perror("clock_gettime");
        return 1;
    }

    interval_ns = interval_us * NS_PER_US;
    deadline_ns = start.boottime_ns + duration_ms * NS_PER_MS;
    next_poll_ns = start.boottime_ns;

    printf("{\"schema_version\":3,\"event\":\"probe_start\"," 
           "\"pid\":%ld,\"realtime_ns\":%" PRIu64 ","
           "\"boottime_ns\":%" PRIu64 ",\"interval_us\":%" PRIu64 ","
           "\"duration_ms\":%" PRIu64 ","
           "\"measurement_mode\":\"application_lineage_syscalls\"",
           (long)getpid(), start.realtime_ns, start.boottime_ns, interval_us,
           duration_ms);
    if (application.name != NULL) {
        fputs(",\"application\":", stdout);
        print_json_string(application.name);
    }
    fputs("}\n", stdout);

    if (application.name != NULL) {
        if (fflush(stdout) != 0) {
            perror("fflush(probe_start)");
            return 1;
        }
        if (spawn_application(&application) != 0) {
            perror("spawn application");
            if (application.pid > 0)
                terminate_application(&application);
            return 1;
        }
    }

    for (;;) {
        uint64_t now_ns = 0;

        /* Only supervise PID 1. These launcher syscalls are not app lineage. */
        do {
            if (application.name != NULL && termination_requested)
                break;
            now_ns = read_boottime_ns();
        } while (now_ns < next_poll_ns);

        if (application.name != NULL && termination_requested) {
            measurement_interrupted = true;
            break;
        }

        if (now_ns >= deadline_ns)
            break;

        next_poll_ns += interval_ns;

        /* Skip missed supervisor polling slots. */
        now_ns = read_boottime_ns();
        if (next_poll_ns <= now_ns) {
            uint64_t missed = (now_ns - next_poll_ns) / interval_ns + 1;
            next_poll_ns += missed * interval_ns;
        }

        if (application.name != NULL && child_state_changed &&
            !application.reaped) {
            int poll_result;

            child_state_changed = 0;
            poll_result = poll_application(&application, "measurement");
            if (poll_result < 0) {
                perror("waitpid(application)");
                measurement_internal_error = true;
                break;
            }
            if (poll_result == 1)
                application_exited_during_measurement = true;
        }
    }

    if (application.name != NULL && !application.reaped) {
        int poll_result = poll_application(&application, "measurement");

        if (poll_result < 0) {
            perror("waitpid(application at summary)");
            measurement_internal_error = true;
        } else if (poll_result == 1) {
            application_exited_during_measurement = true;
        }
    }
    if (application.name != NULL)
        application_alive_at_summary = !application.reaped;

    if (read_cgroup_id(&cgroup_id) != 0)
        cgroup_id_errno = errno;

    if (read_timestamp(&end) != 0) {
        perror("clock_gettime");
        if (application.name != NULL)
            terminate_application(&application);
        return 1;
    }

    printf("{\"schema_version\":3,\"event\":\"probe_summary\"," 
           "\"pid\":%ld,\"realtime_ns\":%" PRIu64 ","
           "\"boottime_ns\":%" PRIu64 ",\"start_realtime_ns\":%" PRIu64 ","
           "\"start_boottime_ns\":%" PRIu64 ","
           "\"measurement_mode\":\"application_lineage_syscalls\","
           "\"cgroup_id\":%" PRIu64 ","
           "\"cgroup_id_errno\":%d,\"evidence_hold_ms\":%" PRIu64,
           (long)getpid(), end.realtime_ns, end.boottime_ns,
           start.realtime_ns, start.boottime_ns, cgroup_id, cgroup_id_errno,
           evidence_hold_ms);

    if (application.name != NULL) {
        fputs(",\"application\":", stdout);
        print_json_string(application.name);
        printf(",\"app_pid\":%ld,\"app_alive_at_summary\":%s,"
               "\"measurement_interrupted\":%s",
               (long)application.pid,
               application_alive_at_summary ? "true" : "false",
               measurement_interrupted ? "true" : "false");
    }
    fputs("}\n", stdout);

    if (application.name == NULL) {
        struct timespec hold = {
            .tv_sec = (time_t)(evidence_hold_ms / UINT64_C(1000)),
            .tv_nsec = (long)((evidence_hold_ms % UINT64_C(1000)) * NS_PER_MS),
        };
        while (nanosleep(&hold, &hold) != 0) {
            if (errno != EINTR) {
                perror("nanosleep(evidence hold)");
                return 1;
            }
        }
        return 0;
    }

    if (terminate_application(&application) != 0) {
        perror("terminate application");
        final_status = 1;
    }
    /*
     * Freeze the application-only counters at the measurement deadline, then
     * keep only PID 1 alive long enough for userspace evidence collection.
     */
    {
        int hold_result = hold_application_evidence(&application,
                                                    evidence_hold_ms);

        if (hold_result < 0) {
            perror("application evidence hold");
            final_status = 1;
        } else if (hold_result > 0) {
            final_status = 1;
        }
    }
    if (application_exited_during_measurement || measurement_interrupted ||
        measurement_internal_error)
        final_status = 1;

    return final_status;
}

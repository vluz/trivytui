#define _XOPEN_SOURCE 700
#define _POSIX_C_SOURCE 200809L

#include <curses.h>
#include <dirent.h>
#include <jansson.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>
#include <sys/wait.h>
#include <time.h>
#include <signal.h>

/* curses-based TUI wrapper around Trivy for filesystem and Docker image scanning. */

/* License: CC0 1.0 Universal */

/* Prototype for realpath when strict feature macros hide it */
extern char *realpath(const char *restrict path, char *restrict resolved_path);

#define INSTALL_SCRIPT "https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif

#define RC_CANCELED 130
#define LAST_ERROR_MAX 8192

typedef struct {
    char **items;
    size_t len;
    size_t cap;
} StrList;

/* Forward declarations */
static void show_message(WINDOW *win, const char *msg);
static bool scroll_view(WINDOW *win, StrList *lines, const char *raw_json);
static void set_last_error(const char *msg);

/* Global exit flag to allow views to signal immediate application exit */
static bool g_exit_requested = false;
/* Cached version strings for the main menu footer. */
static char g_trivy_version[128] = "Trivy: unknown";
static char g_db_version[128] = "DB: unknown";
static char g_last_error[LAST_ERROR_MAX] = "";

enum {
    CLR_DEFAULT = 0,
    CLR_CRITICAL = 1,
    CLR_HIGH,
    CLR_MEDIUM,
    CLR_LOW,
    CLR_UNKNOWN
};

typedef struct {
    int critical;
    int high;
    int medium;
    int low;
    int secrets;
    int licenses;
} SevCounts;

static void bump_severity(SevCounts *counts, const char *sev) {
    if (!sev || !counts) return;
    if (strcasecmp(sev, "CRITICAL") == 0) counts->critical++;
    else if (strcasecmp(sev, "HIGH") == 0) counts->high++;
    else if (strcasecmp(sev, "MEDIUM") == 0) counts->medium++;
    else if (strcasecmp(sev, "LOW") == 0) counts->low++;
}

/* Derive a coarse score from severity counts for the summary header. */
static int compute_score(const SevCounts *counts) {
    // Exponential decay to keep scores granular even with many findings.
    if (!counts) return 100;
    double weighted = counts->critical * 8.0 + counts->high * 4.0 + counts->medium * 2.0 + counts->low * 1.0;
    // Softer decay so real-world images with many findings retain more gradient.
    double score = 100.0 * exp(-0.0025 * weighted);
    if (score < 0.0) score = 0.0;
    if (score > 100.0) score = 100.0;
    return (int)(score + 0.5);
}

/* Basic string list utilities */
/* Release memory owned by a StrList. */
static void strlist_free(StrList *list) {
    if (!list) return;
    for (size_t i = 0; i < list->len; i++) {
        free(list->items[i]);
    }
    free(list->items);
    list->items = NULL;
    list->len = list->cap = 0;
}

/* Append a copy of s into the list. */
static bool strlist_append(StrList *list, const char *s) {
    if (list->len + 1 > list->cap) {
        size_t new_cap = list->cap ? list->cap * 2 : 8;
        char **new_items = realloc(list->items, new_cap * sizeof(char *));
        if (!new_items) return false;
        list->items = new_items;
        list->cap = new_cap;
    }
    list->items[list->len] = strdup(s ? s : "");
    if (!list->items[list->len]) return false;
    list->len++;
    return true;
}

/* Run a shell command and capture stdout/stderr. */
static char *run_command_capture(const char *cmd, int *exit_code) {
    FILE *fp = popen(cmd, "r");
    if (!fp) return NULL;
    size_t cap = 4096;
    size_t len = 0;
    char *buf = malloc(cap);
    if (!buf) {
        pclose(fp);
        return NULL;
    }
    int c;
    while ((c = fgetc(fp)) != EOF) {
        if (len + 1 >= cap) {
            cap *= 2;
            char *nbuf = realloc(buf, cap);
            if (!nbuf) {
                free(buf);
                pclose(fp);
                return NULL;
            }
            buf = nbuf;
        }
        buf[len++] = (char)c;
    }
    buf[len] = '\0';
    int rc = pclose(fp);
    if (exit_code) *exit_code = rc;
    return buf;
}

/* Read a file into a newly allocated string buffer. */
static char *read_file_contents(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;
    size_t cap = 4096, len = 0;
    char *buf = malloc(cap);
    if (!buf) {
        fclose(fp);
        return NULL;
    }
    int c;
    while ((c = fgetc(fp)) != EOF) {
        if (len + 1 >= cap) {
            cap *= 2;
            char *nbuf = realloc(buf, cap);
            if (!nbuf) {
                free(buf);
                fclose(fp);
                return NULL;
            }
            buf = nbuf;
        }
        buf[len++] = (char)c;
    }
    buf[len] = '\0';
    fclose(fp);
    return buf;
}

/* Prompt for a single-line input in the UI. */
static bool prompt_input(WINDOW *win, const char *prompt, char *buf, size_t size, bool allow_empty) {
    if (!win || !buf || size == 0) return false;
    buf[0] = '\0';
    echo();
    curs_set(1);
    nodelay(win, FALSE);
    werase(win);
    int h, w;
    getmaxyx(win, h, w);
    (void)w;
    mvwprintw(win, h / 2 - 1, 2, "%s", prompt ? prompt : "Input:");
    mvwprintw(win, h / 2, 2, "> ");
    wrefresh(win);
    if (wgetnstr(win, buf, (int)(size - 1)) == ERR) {
        noecho();
        curs_set(0);
        return false;
    }
    noecho();
    curs_set(0);
    if (!allow_empty && buf[0] == '\0') return false;
    return true;
}

static StrList strlist_from_text(const char *text) {
    StrList out = {0};
    if (!text || !*text) return out;
    char *copy = strdup(text);
    if (!copy) return out;
    char *saveptr = NULL;
    char *line = strtok_r(copy, "\n", &saveptr);
    while (line) {
        strlist_append(&out, line);
        line = strtok_r(NULL, "\n", &saveptr);
    }
    free(copy);
    if (out.len == 0) {
        strlist_append(&out, "(empty)");
    }
    return out;
}

/* Display the most recent error output, if any. */
static void view_last_error(WINDOW *win) {
    if (!win) return;
    if (g_last_error[0] == '\0') {
        show_message(win, "No recent errors. Press any key.");
        getch();
        return;
    }
    StrList lines = strlist_from_text(g_last_error);
    scroll_view(win, &lines, NULL);
    strlist_free(&lines);
}

/* Ask for a path and save the raw JSON report to disk. */
static void save_report_prompt(WINDOW *win, const char *raw_json) {
    if (!win) return;
    if (!raw_json) {
        show_message(win, "No report to save. Press any key.");
        getch();
        return;
    }
    char path[PATH_MAX];
    if (!prompt_input(win, "Save report as (path):", path, sizeof(path), false)) {
        return;
    }
    size_t path_len = strlen(path);
    bool has_json = (path_len >= 5 && strcasecmp(path + path_len - 5, ".json") == 0);
    if (!has_json) {
        if (path_len + 6 <= sizeof(path)) {
            strcat(path, ".json");
        }
    }
    FILE *fp = fopen(path, "w");
    if (!fp) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Save failed: %s. Press any key.", strerror(errno));
        set_last_error(msg);
        show_message(win, msg);
        getch();
        return;
    }
    size_t raw_len = strlen(raw_json);
    size_t written = fwrite(raw_json, 1, raw_len, fp);
    fclose(fp);
    if (written != raw_len) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Save incomplete. Press any key.");
        set_last_error(msg);
        show_message(win, msg);
        getch();
        return;
    }
    show_message(win, "Report saved. Press any key.");
    getch();
}

static void cancel_process(pid_t pid, int *status) {
    if (pid <= 0) return;
    kill(pid, SIGINT);
    for (int i = 0; i < 10; i++) {
        pid_t r = waitpid(pid, status, WNOHANG);
        if (r == pid) return;
        struct timespec ts = {0, 100000000}; // 100ms
        nanosleep(&ts, NULL);
    }
    kill(pid, SIGKILL);
    waitpid(pid, status, 0);
}

/* Run a command with a spinner; allow cancel and capture stdout/stderr separately. */
static int run_command_with_spinner(const char *const *argv, WINDOW *win, const char *message,
                                    bool *canceled, char **out_str, char **err_str) {
    if (canceled) *canceled = false;
    char tmp_out[] = "/tmp/trivy_tui_outXXXXXX";
    char tmp_err[] = "/tmp/trivy_tui_errXXXXXX";
    int fd_out = mkstemp(tmp_out);
    if (fd_out < 0) return -1;
    int fd_err = mkstemp(tmp_err);
    if (fd_err < 0) {
        close(fd_out);
        unlink(tmp_out);
        return -1;
    }
    pid_t pid = fork();
    if (pid == 0) {
        // Child: redirect stdout/stderr to temp file so UI stays responsive.
        dup2(fd_out, STDOUT_FILENO);
        dup2(fd_err, STDERR_FILENO);
        close(fd_out);
        close(fd_err);
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    } else if (pid < 0) {
        close(fd_out);
        close(fd_err);
        unlink(tmp_out);
        unlink(tmp_err);
        return -1;
    }
    close(fd_out);
    close(fd_err);
    const char frames[] = "|/-\\";
    int idx = 0;
    int status = 0;
    if (win) nodelay(win, TRUE);
    while (1) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == 0) {
            // Parent: keep drawing a lightweight spinner while scan runs.
            if (win) {
                int h, w;
                getmaxyx(win, h, w);
                (void)w;
                werase(win);
                mvwprintw(win, h / 2, 2, "%s %c", message ? message : "Scanning...", frames[idx % 4]);
                if (h / 2 + 1 < h) mvwprintw(win, h / 2 + 1, 2, "Press c to cancel");
                wrefresh(win);
                idx++;
            }
            if (win) {
                int ch = wgetch(win);
                if (ch == 'c' || ch == 'C') {
                    cancel_process(pid, &status);
                    if (canceled) *canceled = true;
                    break;
                }
            }
            struct timespec ts = {0, 100000000}; // 100ms
            nanosleep(&ts, NULL);
            continue;
        } else if (r == -1) {
            status = 1;
            break;
        } else {
            break;
        }
    }
    if (win) nodelay(win, FALSE);

    // Keep stderr separate so non-JSON warnings don't corrupt JSON output.
    if (out_str) *out_str = read_file_contents(tmp_out);
    if (err_str) *err_str = read_file_contents(tmp_err);
    unlink(tmp_out);
    unlink(tmp_err);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return 1;
}

/* Detect flag-related failures in Trivy output. */
static bool output_has_flag_error(const char *out, const char *flag) {
    if (!out || !flag) return false;
    if (!strstr(out, flag)) return false;
    return strstr(out, "unknown flag")
        || strstr(out, "unknown shorthand flag")
        || strstr(out, "flag provided but not defined")
        || strstr(out, "unknown option")
        || strstr(out, "unrecognized option");
}

/* Build Trivy scanner list based on current toggles. */
static void build_scanner_list(char *buf, size_t buf_size, bool scan_secrets, bool scan_licenses) {
    if (!buf || buf_size == 0) return;
    size_t used = 0;
    used += snprintf(buf + used, buf_size - used, "vuln");
    if (scan_secrets && used < buf_size) {
        used += snprintf(buf + used, buf_size - used, ",secret");
    }
    if (scan_licenses && used < buf_size) {
        snprintf(buf + used, buf_size - used, ",license");
    }
}

enum SeverityLevel {
    SEV_ALL = 0,
    SEV_LOW,
    SEV_MEDIUM,
    SEV_HIGH,
    SEV_CRITICAL,
    SEV_COUNT
};

static const char *severity_label(int level) {
    switch (level) {
        case SEV_LOW: return "Low+";
        case SEV_MEDIUM: return "Medium+";
        case SEV_HIGH: return "High+";
        case SEV_CRITICAL: return "Critical";
        case SEV_ALL:
        default:
            return "All";
    }
}

static bool build_severity_list(int level, char *buf, size_t size) {
    if (!buf || size == 0) return false;
    switch (level) {
        case SEV_LOW:
            snprintf(buf, size, "LOW,MEDIUM,HIGH,CRITICAL");
            return true;
        case SEV_MEDIUM:
            snprintf(buf, size, "MEDIUM,HIGH,CRITICAL");
            return true;
        case SEV_HIGH:
            snprintf(buf, size, "HIGH,CRITICAL");
            return true;
        case SEV_CRITICAL:
            snprintf(buf, size, "CRITICAL");
            return true;
        case SEV_ALL:
        default:
            buf[0] = '\0';
            return false;
    }
}

/* Apply root-only skip list when target is "/". */
static const char *root_skip_dirs_for_target(const char *target, bool use_root_skip, const char *root_skip_dirs) {
    if (!use_root_skip || !root_skip_dirs || !*root_skip_dirs) return NULL;
    if (!target) return NULL;
    if (strcmp(target, "/") == 0) return root_skip_dirs;
    return NULL;
}

static void set_last_error(const char *msg) {
    if (!msg || !*msg) return;
    size_t len = strlen(msg);
    if (len >= sizeof(g_last_error)) len = sizeof(g_last_error) - 1;
    memcpy(g_last_error, msg, len);
    g_last_error[len] = '\0';
}

/* Run a command with a spinner, allow cancel, and kill it after timeout_sec (0 disables timeout). */
static int run_command_with_spinner_timeout(const char *const *argv, WINDOW *win, const char *message,
                                            int timeout_sec, bool *timed_out, bool *canceled,
                                            char **out_str, char **err_str) {
    if (timed_out) *timed_out = false;
    if (canceled) *canceled = false;
    char tmp_out[] = "/tmp/trivy_tui_outXXXXXX";
    char tmp_err[] = "/tmp/trivy_tui_errXXXXXX";
    int fd_out = mkstemp(tmp_out);
    if (fd_out < 0) return -1;
    int fd_err = mkstemp(tmp_err);
    if (fd_err < 0) {
        close(fd_out);
        unlink(tmp_out);
        return -1;
    }
    pid_t pid = fork();
    if (pid == 0) {
        // Child: redirect stdout/stderr to temp file so UI stays responsive.
        dup2(fd_out, STDOUT_FILENO);
        dup2(fd_err, STDERR_FILENO);
        close(fd_out);
        close(fd_err);
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    } else if (pid < 0) {
        close(fd_out);
        close(fd_err);
        unlink(tmp_out);
        unlink(tmp_err);
        return -1;
    }
    close(fd_out);
    close(fd_err);
    const char frames[] = "|/-\\";
    int idx = 0;
    int status = 0;
    time_t start = time(NULL);
    if (win) nodelay(win, TRUE);
    while (1) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == 0) {
            if (timeout_sec > 0 && time(NULL) - start >= timeout_sec) {
                kill(pid, SIGKILL);
                waitpid(pid, &status, 0);
                if (timed_out) *timed_out = true;
                break;
            }
            // Parent: keep drawing a lightweight spinner while command runs.
            if (win) {
                int h, w;
                getmaxyx(win, h, w);
                (void)w;
                werase(win);
                mvwprintw(win, h / 2, 2, "%s %c", message ? message : "Working...", frames[idx % 4]);
                if (h / 2 + 1 < h) mvwprintw(win, h / 2 + 1, 2, "Press c to cancel");
                wrefresh(win);
                idx++;
            }
            if (win) {
                int ch = wgetch(win);
                if (ch == 'c' || ch == 'C') {
                    cancel_process(pid, &status);
                    if (canceled) *canceled = true;
                    break;
                }
            }
            struct timespec ts = {0, 100000000}; // 100ms
            nanosleep(&ts, NULL);
            continue;
        } else if (r == -1) {
            status = 1;
            break;
        } else {
            break;
        }
    }
    if (win) nodelay(win, FALSE);

    if (out_str) *out_str = read_file_contents(tmp_out);
    if (err_str) *err_str = read_file_contents(tmp_err);
    unlink(tmp_out);
    unlink(tmp_err);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return 1;
}

/* Build Trivy argv with optional filters and limits. */
static int build_trivy_args(const char *mode, const char *target,
                            const char *scanner_flag, const char *scanner_value,
                            bool include_license_full,
                            const char *severity, const char *ignorefile,
                            const char *timeout, const char *skip_dirs,
                            const char **argv, int argv_cap) {
    if (!mode || !target || !argv || argv_cap <= 0) return -1;
    int idx = 0;
#define PUSH_ARG(val) do { if (idx >= argv_cap - 1) return -1; argv[idx++] = (val); } while (0)
    PUSH_ARG("trivy");
    PUSH_ARG(mode);
    if (scanner_flag && scanner_value) {
        PUSH_ARG(scanner_flag);
        PUSH_ARG(scanner_value);
    }
    if (include_license_full) {
        PUSH_ARG("--license-full");
    }
    if (severity && *severity) {
        PUSH_ARG("--severity");
        PUSH_ARG(severity);
    }
    if (ignorefile && *ignorefile) {
        PUSH_ARG("--ignorefile");
        PUSH_ARG(ignorefile);
    }
    if (timeout && *timeout) {
        PUSH_ARG("--timeout");
        PUSH_ARG(timeout);
    }
    if (skip_dirs && *skip_dirs) {
        PUSH_ARG("--skip-dirs");
        PUSH_ARG(skip_dirs);
    }
    PUSH_ARG("--format");
    PUSH_ARG("json");
    PUSH_ARG("--quiet");
    PUSH_ARG(target);
    argv[idx] = NULL;
    return idx;
#undef PUSH_ARG
}

/* Run Trivy scan and retry with older flags if needed. */
static int run_trivy_scan_with_fallback(const char *mode, const char *target, WINDOW *win,
                                        const char *message, bool scan_secrets, bool scan_licenses,
                                        int severity_level, const char *ignorefile,
                                        const char *timeout, const char *skip_dirs,
                                        char **out_str) {
    char *out = NULL;
    char *err = NULL;
    bool canceled = false;
    char scanners[64];
    char severity[64];
    build_scanner_list(scanners, sizeof(scanners), scan_secrets, scan_licenses);
    build_severity_list(severity_level, severity, sizeof(severity));
    const char *argv1[24];
    if (build_trivy_args(mode, target, "--scanners", scanners, scan_licenses,
                         severity, ignorefile, timeout, skip_dirs,
                         argv1, (int)(sizeof(argv1) / sizeof(argv1[0]))) < 0) {
        set_last_error("Failed to build Trivy arguments.");
        return 1;
    }
    int rc = run_command_with_spinner(argv1, win, message, &canceled, &out, &err);
    if (canceled) {
        free(out);
        free(err);
        return RC_CANCELED;
    }
    if (rc == 0 && out) {
        free(err);
        if (out_str) *out_str = out;
        else free(out);
        return 0;
    }

    // Fallback order: drop --license-full, then replace --scanners, then drop all scanner flags.
    bool bad_license_full = output_has_flag_error(err, "--license-full") || output_has_flag_error(out, "--license-full");
    bool bad_scanners = output_has_flag_error(err, "--scanners") || output_has_flag_error(out, "--scanners");
    if (bad_license_full && !bad_scanners) {
        free(out);
        free(err);
        out = NULL;
        err = NULL;
        const char *argv2[24];
        if (build_trivy_args(mode, target, "--scanners", scanners, false,
                             severity, ignorefile, timeout, skip_dirs,
                             argv2, (int)(sizeof(argv2) / sizeof(argv2[0]))) < 0) {
            set_last_error("Failed to build Trivy arguments.");
            return 1;
        }
        rc = run_command_with_spinner(argv2, win, message, &canceled, &out, &err);
        if (canceled) {
            free(out);
            free(err);
            return RC_CANCELED;
        }
        if (rc == 0 && out) {
            free(err);
            if (out_str) *out_str = out;
            else free(out);
            return 0;
        }
        bad_scanners = bad_scanners
            || output_has_flag_error(err, "--scanners")
            || output_has_flag_error(out, "--scanners");
    }

    if (bad_scanners) {
        free(out);
        free(err);
        out = NULL;
        err = NULL;
        const char *argv3[24];
        if (build_trivy_args(mode, target, "--security-checks", scanners, false,
                             severity, ignorefile, timeout, skip_dirs,
                             argv3, (int)(sizeof(argv3) / sizeof(argv3[0]))) < 0) {
            set_last_error("Failed to build Trivy arguments.");
            return 1;
        }
        rc = run_command_with_spinner(argv3, win, message, &canceled, &out, &err);
        if (canceled) {
            free(out);
            free(err);
            return RC_CANCELED;
        }
        if (rc == 0 && out) {
            free(err);
            if (out_str) *out_str = out;
            else free(out);
            return 0;
        }
        if (output_has_flag_error(err, "--security-checks") || output_has_flag_error(out, "--security-checks")) {
            free(out);
            free(err);
            out = NULL;
            err = NULL;
            const char *argv4[24];
            if (build_trivy_args(mode, target, NULL, NULL, false,
                                 severity, ignorefile, timeout, skip_dirs,
                                 argv4, (int)(sizeof(argv4) / sizeof(argv4[0]))) < 0) {
                set_last_error("Failed to build Trivy arguments.");
                return 1;
            }
            rc = run_command_with_spinner(argv4, win, message, &canceled, &out, &err);
            if (canceled) {
                free(out);
                free(err);
                return RC_CANCELED;
            }
            if (rc == 0 && out) {
                free(err);
                if (out_str) *out_str = out;
                else free(out);
                return 0;
            }
        }
    }

    if (rc != 0) {
        if (err && *err) set_last_error(err);
        else if (out && *out) set_last_error(out);
        else set_last_error("Trivy scan failed.");
    }
    free(err);
    if (out_str) *out_str = out;
    else free(out);
    return rc;
}

/* True if a command is available on PATH. */
static bool command_exists(const char *cmd) {
    char full[256];
    snprintf(full, sizeof(full), "command -v %s >/dev/null 2>&1", cmd);
    int rc = system(full);
    return rc == 0;
}

/* Check that Trivy is available on PATH (no auto-install for airgapped use). */
static bool install_trivy(void) {
    return command_exists("trivy");
}

/* Refresh the Trivy DB with a timeout and cancel; return false on error and pass message to caller. */
static bool update_trivy_db(WINDOW *win, char **msg_out) {
    const char *argv[] = {"trivy", "image", "--download-db-only", "--no-progress", NULL};
    char *out = NULL;
    char *err = NULL;
    bool timed_out = false;
    bool canceled = false;
    int rc = run_command_with_spinner_timeout(argv, win, "Updating Trivy DB...", 120,
                                              &timed_out, &canceled, &out, &err);
    if (rc == 0) {
        free(out);
        free(err);
        return true;
    }
    if (msg_out) {
        if (timed_out) {
            *msg_out = strdup("Trivy DB update timed out.");
            free(out);
            free(err);
        } else if (canceled) {
            *msg_out = strdup("Trivy DB update canceled.");
            free(out);
            free(err);
        } else if (err) {
            *msg_out = err;
            free(out);
        } else {
            *msg_out = out;
        }
        if (*msg_out) set_last_error(*msg_out);
    } else {
        if (err && *err) set_last_error(err);
        else if (out && *out) set_last_error(out);
        free(out);
        free(err);
    }
    return false;
}

static bool get_trivy_cache_dir(char *buf, size_t size) {
    if (!buf || size == 0) return false;
    const char *cache = getenv("TRIVY_CACHE_DIR");
    if (cache && *cache) {
        snprintf(buf, size, "%s", cache);
        return true;
    }
    const char *xdg = getenv("XDG_CACHE_HOME");
    if (xdg && *xdg) {
        snprintf(buf, size, "%s", xdg);
        return true;
    }
    const char *home = getenv("HOME");
    if (home && *home) {
        snprintf(buf, size, "%s/.cache", home);
        return true;
    }
    return false;
}

static bool build_trivy_db_path(char *buf, size_t size, const char *cache, const char *file) {
    if (!buf || size == 0 || !cache || !file) return false;
    const char *suffix = "/trivy/db/";
    size_t cache_len = strlen(cache);
    size_t suffix_len = strlen(suffix);
    size_t file_len = strlen(file);
    size_t need = cache_len + suffix_len + file_len + 1;
    if (need > size) return false;
    memcpy(buf, cache, cache_len);
    memcpy(buf + cache_len, suffix, suffix_len);
    memcpy(buf + cache_len + suffix_len, file, file_len);
    buf[cache_len + suffix_len + file_len] = '\0';
    return true;
}

static void format_age(time_t mtime, char *buf, size_t size) {
    if (!buf || size == 0) return;
    time_t now = time(NULL);
    if (mtime <= 0 || now < mtime) {
        snprintf(buf, size, "updated: unknown");
        return;
    }
    long diff = (long)difftime(now, mtime);
    if (diff < 60) {
        snprintf(buf, size, "updated: just now");
    } else if (diff < 3600) {
        snprintf(buf, size, "updated: %ldm ago", diff / 60);
    } else if (diff < 86400) {
        snprintf(buf, size, "updated: %ldh ago", diff / 3600);
    } else {
        snprintf(buf, size, "updated: %ldd ago", diff / 86400);
    }
}

static void get_db_status(char *buf, size_t size) {
    if (!buf || size == 0) return;
    char cache[PATH_MAX];
    if (!get_trivy_cache_dir(cache, sizeof(cache))) {
        snprintf(buf, size, "DB: unknown (no cache dir)");
        return;
    }

    const char *files[] = {"metadata.json", "trivy.db"};
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        char path[PATH_MAX];
        if (!build_trivy_db_path(path, sizeof(path), cache, files[i])) {
            continue;
        }
        struct stat st;
        if (stat(path, &st) == 0) {
            char age[64];
            format_age(st.st_mtime, age, sizeof(age));
            snprintf(buf, size, "DB: present (%s)", age);
            return;
        }
    }
    snprintf(buf, size, "DB: missing");
}

static void get_trivy_version_string(char *buf, size_t size) {
    if (!buf || size == 0) return;
    if (!command_exists("trivy")) {
        snprintf(buf, size, "Trivy: not found");
        return;
    }
    int rc = 0;
    char *out = run_command_capture("trivy --version 2>/dev/null", &rc);
    if (!out || rc != 0) {
        free(out);
        snprintf(buf, size, "Trivy: unknown");
        return;
    }
    char *saveptr = NULL;
    char *line = strtok_r(out, "\n", &saveptr);
    const char *ver = NULL;
    while (line) {
        char *p = strstr(line, "Version:");
        if (p) {
            p += strlen("Version:");
            while (*p == ' ' || *p == '\t') p++;
            if (*p) {
                ver = p;
                break;
            }
        }
        line = strtok_r(NULL, "\n", &saveptr);
    }
    if (ver && *ver) {
        snprintf(buf, size, "Trivy: %s", ver);
    } else {
        snprintf(buf, size, "Trivy: unknown");
    }
    free(out);
}

static void get_db_version_string(char *buf, size_t size) {
    if (!buf || size == 0) return;
    char cache[PATH_MAX];
    if (!get_trivy_cache_dir(cache, sizeof(cache))) {
        snprintf(buf, size, "DB: unknown");
        return;
    }
    char path[PATH_MAX];
    if (!build_trivy_db_path(path, sizeof(path), cache, "metadata.json")) {
        snprintf(buf, size, "DB: unknown");
        return;
    }
    char *contents = read_file_contents(path);
    if (!contents) {
        snprintf(buf, size, "DB: missing");
        return;
    }
    json_error_t err;
    json_t *root = json_loads(contents, 0, &err);
    free(contents);
    if (!root) {
        snprintf(buf, size, "DB: unknown");
        return;
    }
    json_t *ver = json_object_get(root, "Version");
    if (!ver) ver = json_object_get(root, "SchemaVersion");
    json_t *updated = json_object_get(root, "UpdatedAt");
    if (!updated) updated = json_object_get(root, "DownloadedAt");
    if (!updated) updated = json_object_get(root, "NextUpdate");

    char version_part[64] = "";
    char updated_part[64] = "";
    if (json_is_integer(ver)) {
        long long v = json_integer_value(ver);
        snprintf(version_part, sizeof(version_part), "version %lld", v);
    } else if (json_is_string(ver)) {
        const char *v = json_string_value(ver);
        if (v && *v) snprintf(version_part, sizeof(version_part), "version %s", v);
    }

    if (json_is_string(updated)) {
        const char *u = json_string_value(updated);
        if (u && *u) {
            snprintf(updated_part, sizeof(updated_part), "updated %.10s", u);
        }
    }

    if (version_part[0] && updated_part[0]) {
        snprintf(buf, size, "DB: %s (%s)", version_part, updated_part);
    } else if (version_part[0]) {
        snprintf(buf, size, "DB: %s", version_part);
    } else if (updated_part[0]) {
        snprintf(buf, size, "DB: %s", updated_part);
    } else {
        snprintf(buf, size, "DB: unknown");
    }
    json_decref(root);
}

static void update_version_cache(void) {
    get_trivy_version_string(g_trivy_version, sizeof(g_trivy_version));
    get_db_version_string(g_db_version, sizeof(g_db_version));
}

static void format_line(char *buf, size_t size, const char *label, const char *value, int max_width) {
    if (!buf || size == 0) return;
    snprintf(buf, size, "%s%s", label, value ? value : "");
    if (max_width > 0 && (int)strlen(buf) > max_width) {
        if (max_width >= 3) {
            buf[max_width - 3] = '.';
            buf[max_width - 2] = '.';
            buf[max_width - 1] = '.';
        }
        buf[max_width] = '\0';
    }
}

enum ConfirmResult {
    CONFIRM_START = 0,
    CONFIRM_BACK,
    CONFIRM_MENU,
    CONFIRM_EXIT
};

/* Scan summary prompt before running a scan (auto-start with cancel/back). */
static int confirm_scan(WINDOW *win, const char *mode_label, const char *target,
                        bool scan_secrets, bool scan_licenses,
                        int severity_level, const char *ignorefile,
                        const char *timeout, bool use_root_skip, const char *root_skip_dirs) {
    char scanners[64];
    char db_status[128];
    char severity_line[64];
    const char *root_skips = root_skip_dirs_for_target(target, use_root_skip, root_skip_dirs);
    bool is_root_target = (target && strcmp(target, "/") == 0);
    build_scanner_list(scanners, sizeof(scanners), scan_secrets, scan_licenses);
    get_db_status(db_status, sizeof(db_status));
    snprintf(severity_line, sizeof(severity_line), "Severity: %s", severity_label(severity_level));
    keypad(win, TRUE);
    time_t end_time = time(NULL) + 5;
    if (win) nodelay(win, TRUE);
    while (1) {
        werase(win);
        int h, w;
        getmaxyx(win, h, w);
        (void)w;
        mvwprintw(win, 1, 2, "Scan summary");
        int max_line = w - 6;
        if (max_line < 10) max_line = 10;
        char line[PATH_MAX + 64];
        int row = 3;
        format_line(line, sizeof(line), "Mode: ", mode_label ? mode_label : "", max_line);
        mvwprintw(win, row++, 4, "%.*s", max_line, line);
        format_line(line, sizeof(line), "Target: ", target ? target : "", max_line);
        mvwprintw(win, row++, 4, "%.*s", max_line, line);
        format_line(line, sizeof(line), "Scanners: ", scanners, max_line);
        mvwprintw(win, row++, 4, "%.*s", max_line, line);
        format_line(line, sizeof(line), "", db_status, max_line);
        mvwprintw(win, row++, 4, "%.*s", max_line, line);
        format_line(line, sizeof(line), "", severity_line, max_line);
        mvwprintw(win, row++, 4, "%.*s", max_line, line);
        if (ignorefile && *ignorefile) {
            format_line(line, sizeof(line), "Ignore: ", ignorefile, max_line);
        } else {
            format_line(line, sizeof(line), "Ignore: ", "(none)", max_line);
        }
        mvwprintw(win, row++, 4, "%.*s", max_line, line);
        if (timeout && *timeout) {
            format_line(line, sizeof(line), "Timeout: ", timeout, max_line);
        } else {
            format_line(line, sizeof(line), "Timeout: ", "(none)", max_line);
        }
        mvwprintw(win, row++, 4, "%.*s", max_line, line);
        if (root_skips) {
            format_line(line, sizeof(line), "Root skips: ", root_skips, max_line);
        } else if (is_root_target) {
            format_line(line, sizeof(line), "Root skips: ", use_root_skip ? "(none)" : "(off)", max_line);
        } else {
            format_line(line, sizeof(line), "Root skips: ", "(n/a)", max_line);
        }
        mvwprintw(win, row++, 4, "%.*s", max_line, line);
        int remaining = (int)difftime(end_time, time(NULL));
        if (remaining < 0) remaining = 0;
        mvwprintw(win, h - 2, 2, "Auto-start in %ds  Enter start  b back  m menu  e exit", remaining);
        wrefresh(win);
        int ch = wgetch(win);
        if (ch == '\n' || ch == KEY_ENTER) {
            if (win) nodelay(win, FALSE);
            return CONFIRM_START;
        }
        if (ch == 'b' || ch == 'c' || ch == 27) {
            if (win) nodelay(win, FALSE);
            return CONFIRM_BACK;
        }
        if (ch == 'm') {
            if (win) nodelay(win, FALSE);
            return CONFIRM_MENU;
        }
        if (ch == 'e') {
            g_exit_requested = true;
            if (win) nodelay(win, FALSE);
            return CONFIRM_EXIT;
        }
        if (remaining <= 0) {
            if (win) nodelay(win, FALSE);
            return CONFIRM_START;
        }
        struct timespec ts = {0, 100000000}; // 100ms
        nanosleep(&ts, NULL);
    }
}

/* Main menu renderer and selector */
static int menu(WINDOW *win, const char *title, const char **options, int count) {
    (void)title;
    int current = 0;
    keypad(win, TRUE);
    while (1) {
        werase(win);
        int h, w;
        getmaxyx(win, h, w);
        (void)w;
        if (has_colors()) wattron(win, A_BOLD | COLOR_PAIR(CLR_UNKNOWN));
        mvwprintw(win, 1, 2, "TRIVY TUI");
        if (has_colors()) wattroff(win, A_BOLD | COLOR_PAIR(CLR_UNKNOWN));
        mvwprintw(win, 2, 2, ""); // blank line under title
        for (int i = 0; i < count; i++) {
            if (i == current) wattron(win, A_REVERSE);
            mvwprintw(win, 3 + i, 4, "%s", options[i]);
            if (i == current) wattroff(win, A_REVERSE);
        }
        int last_option_row = 3 + count - 1;
        int info_row = h - 4;
        int info_row2 = h - 3;
        if (info_row > last_option_row && info_row2 > last_option_row) {
            mvwprintw(win, info_row, 2, "%s", g_trivy_version);
            mvwprintw(win, info_row2, 2, "%s", g_db_version);
        }
        mvwprintw(win, h - 2, 2, "Use arrows, Enter to select, q to quit.");
        wrefresh(win);
        int ch = wgetch(win);
        if (ch == KEY_UP || ch == 'k') current = (current - 1 + count) % count;
        else if (ch == KEY_DOWN || ch == 'j') current = (current + 1) % count;
        else if (ch == '\n' || ch == KEY_ENTER) return current;
        else if (ch == 'q') return count - 1;
    }
}

/* Settings menu for scan toggles, filters, timeouts, root skips, and manual DB refresh/log view. */
static void settings_menu(WINDOW *win, bool *scan_secrets, bool *scan_licenses,
                          int *severity_level, char *ignore_file, size_t ignore_size,
                          char *timeout_value, size_t timeout_size,
                          bool *use_root_skip, char *root_skip_dirs, size_t root_skip_size) {
    int current = 0;
    keypad(win, TRUE);
    while (1) {
        char secrets[64];
        char licenses[64];
        char severity[64];
        char ignore[PATH_MAX];
        char timeout[64];
        char root_skip_toggle[64];
        char root_skip_line[PATH_MAX];
        snprintf(secrets, sizeof(secrets), "Secrets scan: %s", *scan_secrets ? "ON" : "OFF");
        snprintf(licenses, sizeof(licenses), "Licenses scan: %s", *scan_licenses ? "ON" : "OFF");
        snprintf(severity, sizeof(severity), "Severity: %s", severity_label(*severity_level));
        if (ignore_file && *ignore_file) {
            snprintf(ignore, sizeof(ignore), "Ignore file: %s", ignore_file);
        } else {
            snprintf(ignore, sizeof(ignore), "Ignore file: (none)");
        }
        if (timeout_value && *timeout_value) {
            snprintf(timeout, sizeof(timeout), "Timeout: %s", timeout_value);
        } else {
            snprintf(timeout, sizeof(timeout), "Timeout: (none)");
        }
        snprintf(root_skip_toggle, sizeof(root_skip_toggle), "Root skips: %s", (use_root_skip && *use_root_skip) ? "ON" : "OFF");
        if (root_skip_dirs && *root_skip_dirs) {
            snprintf(root_skip_line, sizeof(root_skip_line), "Root skip dirs: %s", root_skip_dirs);
        } else {
            snprintf(root_skip_line, sizeof(root_skip_line), "Root skip dirs: (none)");
        }
        const char *options[] = {
            secrets,
            licenses,
            severity,
            ignore,
            timeout,
            root_skip_toggle,
            root_skip_line,
            "Redownload DB (online)",
            "View last error",
            "Back"
        };
        int count = 10;

        werase(win);
        int h, w;
        getmaxyx(win, h, w);
        (void)w;
        mvwprintw(win, 1, 2, "Settings");
        for (int i = 0; i < count; i++) {
            if (i == current) wattron(win, A_REVERSE);
            mvwprintw(win, 3 + i, 4, "%s", options[i]);
            if (i == current) wattroff(win, A_REVERSE);
        }
        mvwprintw(win, h - 2, 2, "Arrows/Enter select  b back  e exit");
        wrefresh(win);

        int ch = wgetch(win);
        if (ch == KEY_UP || ch == 'k') current = (current - 1 + count) % count;
        else if (ch == KEY_DOWN || ch == 'j') current = (current + 1) % count;
        else if (ch == 'e') { g_exit_requested = true; return; }
        else if (ch == 'b' || ch == 'm' || ch == 27) return;
        else if (ch == '\n' || ch == KEY_ENTER) {
            if (current == 0) {
                *scan_secrets = !*scan_secrets;
            } else if (current == 1) {
                *scan_licenses = !*scan_licenses;
            } else if (current == 2) {
                if (severity_level) {
                    *severity_level = (*severity_level + 1) % SEV_COUNT;
                }
            } else if (current == 3) {
                char input[PATH_MAX];
                if (prompt_input(win, "Ignore file path (empty clears):", input, sizeof(input), true)) {
                    if (ignore_file && ignore_size > 0) {
                        strncpy(ignore_file, input, ignore_size - 1);
                        ignore_file[ignore_size - 1] = '\0';
                    }
                }
            } else if (current == 4) {
                char input[64];
                if (prompt_input(win, "Timeout (e.g. 10m, empty clears):", input, sizeof(input), true)) {
                    if (timeout_value && timeout_size > 0) {
                        strncpy(timeout_value, input, timeout_size - 1);
                        timeout_value[timeout_size - 1] = '\0';
                    }
                }
            } else if (current == 5) {
                if (use_root_skip) *use_root_skip = !*use_root_skip;
            } else if (current == 6) {
                char input[PATH_MAX];
                if (prompt_input(win, "Root skip dirs (comma list, empty clears):", input, sizeof(input), true)) {
                    if (root_skip_dirs && root_skip_size > 0) {
                        strncpy(root_skip_dirs, input, root_skip_size - 1);
                        root_skip_dirs[root_skip_size - 1] = '\0';
                    }
                }
            } else if (current == 7) {
                if (!install_trivy()) {
                    set_last_error("Trivy not found in PATH.");
                    show_message(win, "Trivy not found in PATH. Install it and retry.");
                    getch();
                    continue;
                }
                char *msg = NULL;
                bool ok = update_trivy_db(win, &msg);
                if (ok) {
                    show_message(win, "DB updated. Press any key.");
                    update_version_cache();
                } else {
                    show_message(win, msg ? msg : "DB update failed. Press any key.");
                }
                free(msg);
                getch();
            } else if (current == 8) {
                view_last_error(win);
            } else {
                return;
            }
        }
    }
}

/* Simple directory listing (skips hidden entries, host-root shows only "/"). */
static bool list_directory(const char *path, StrList *out, bool at_host_root) {
    if (at_host_root) {
        return strlist_append(out, "/");
    }
    DIR *dir = opendir(path);
    if (!dir) return false;
    struct dirent *de;
    strlist_append(out, "..");
    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.') continue;
        char full[PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", path, de->d_name);
        struct stat st;
        if (stat(full, &st) == 0 && S_ISDIR(st.st_mode)) {
            char name[PATH_MAX];
            snprintf(name, sizeof(name), "%s/", de->d_name);
            strlist_append(out, name);
        } else {
            strlist_append(out, de->d_name);
        }
    }
    closedir(dir);
    return true;
}

/* Navigate up one level; stepping above "/" enters host-root view. */
static void navigate_up(char *current, size_t current_size, bool *at_host_root) {
    if (!current || !at_host_root) return;
    if (*at_host_root) return;
    if (strcmp(current, "/") == 0) {
        *at_host_root = true;
        return;
    }
    char parent[PATH_MAX];
    strncpy(parent, current, sizeof(parent) - 1);
    parent[sizeof(parent) - 1] = '\0';
    char *slash = strrchr(parent, '/');
    if (slash && slash != parent) *slash = '\0'; else strcpy(parent, "/");
    strncpy(current, parent, current_size - 1);
    current[current_size - 1] = '\0';
}

/* Interactive directory browser; includes a host-root view above "/". */
static char *browse_directories(WINDOW *win, const char *start) {
    char current[PATH_MAX];
    bool at_host_root = false;
    char hostname[HOST_NAME_MAX + 1] = "host";
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        strncpy(hostname, "host", sizeof(hostname) - 1);
    }
    hostname[sizeof(hostname) - 1] = '\0';
    if (!realpath(start, current)) {
        snprintf(current, sizeof(current), "%s", start);
    }
    bool reset_once = false;
    keypad(win, TRUE);
    while (1) {
        StrList entries = {0};
        if (!list_directory(current, &entries, at_host_root) || entries.len == 0) {
            strlist_free(&entries);
            if (!reset_once) {
                reset_once = true;
                if (getcwd(current, sizeof(current)) != NULL) {
                    // If stored path is no longer accessible, fall back to CWD once.
                    continue; // retry from cwd
                }
            }
            show_message(win, "Cannot read directory. Press any key.");
            getch();
            return NULL;
        }
        int current_idx = 0;
        int offset = 0;
        int choice = -1;
        int last_key = 0;
        while (1) {
            werase(win);
            int h, w;
            getmaxyx(win, h, w);
            (void)w;
            mvwprintw(win, 1, 2, "Browsing: %s", at_host_root ? hostname : current);
            int usable = h - 4;
            if (usable < 1) usable = 1;
        for (int i = 0; i < usable && offset + i < (int)entries.len; i++) {
            int idx = offset + i;
            if (idx == current_idx) wattron(win, A_REVERSE | A_BOLD);
            mvwprintw(win, 2 + i, 4, "%s", entries.items[idx]);
            if (idx == current_idx) wattroff(win, A_REVERSE | A_BOLD);
        }
            mvwprintw(win, h - 2, 2, "Enter=open  Space=select (highlighted)  b=back  m=menu  e=exit");
            wrefresh(win);
            int ch = wgetch(win);
            last_key = ch;
            if (ch == KEY_UP || ch == 'k') current_idx = (current_idx - 1 + entries.len) % entries.len;
            else if (ch == KEY_DOWN || ch == 'j') current_idx = (current_idx + 1) % entries.len;
            else if (ch == KEY_NPAGE) current_idx = ((current_idx + usable) < (int)entries.len) ? current_idx + usable : (int)entries.len - 1;
            else if (ch == KEY_PPAGE) current_idx = (current_idx - usable > 0) ? current_idx - usable : 0;
            else if (ch == 'e') { g_exit_requested = true; choice = -2; break; }
            else if (ch == 'm') { choice = -2; break; }
            else if (ch == 'b' || ch == 27) { choice = -1; break; }
            else if (ch == ' ') { choice = current_idx; break; }
            else if (ch == '\n' || ch == KEY_ENTER) { choice = current_idx; break; }
            if (current_idx < offset) offset = current_idx;
            else if (current_idx >= offset + usable) offset = current_idx - usable + 1;
        }

        if (choice == -2) {
            // 'm' or 'e' requested; return to caller to unwind to main loop.
            strlist_free(&entries);
            return NULL;
        }
        if (choice < 0) {
            // 'b' navigates up one directory.
            strlist_free(&entries);
            navigate_up(current, sizeof(current), &at_host_root);
            continue;
        }

        char selected[PATH_MAX];
        // Build the selected path safely into a fixed buffer.
        char *entry_name = strdup(entries.items[choice]);
        if (!entry_name) {
            strlist_free(&entries);
            show_message(win, "Memory error. Press any key.");
            getch();
            return NULL;
        }
        if (at_host_root) {
            snprintf(selected, sizeof(selected), "/");
        } else {
            size_t base = strlen(current);
            size_t extra = strlen(entry_name);
            bool needs_sep = (base > 0 && current[base - 1] != '/');
            size_t need = base + (needs_sep ? 1 : 0) + extra + 1;
            if (need > sizeof(selected)) {
                strlist_free(&entries);
                free(entry_name);
                show_message(win, "Path too long. Press any key.");
                getch();
                continue;
            }
            memcpy(selected, current, base);
            if (needs_sep) {
                selected[base] = '/';
                memcpy(selected + base + 1, entry_name, extra);
                selected[base + 1 + extra] = '\0';
            } else {
                memcpy(selected + base, entry_name, extra);
                selected[base + extra] = '\0';
            }
        }
        strlist_free(&entries);

        struct stat st;
        if (stat(selected, &st) == 0 && S_ISDIR(st.st_mode)) {
            if (at_host_root) {
                if (last_key == ' ') {
                    char *res = strdup("/");
                    free(entry_name);
                    return res;
                }
                strncpy(current, "/", sizeof(current) - 1);
                current[sizeof(current) - 1] = '\0';
                at_host_root = false;
                free(entry_name);
                continue;
            }
            if (strcmp(entry_name, "..") == 0) {
                // Explicit ".." entry behaves like a parent navigation.
                navigate_up(current, sizeof(current), &at_host_root);
                free(entry_name);
                continue;
            }
            if (last_key == ' ') {
                // Space selects current directory; enter descends into it.
                int h, w;
                getmaxyx(win, h, w);
                (void)w;
                wattron(win, A_BOLD);
                mvwprintw(win, h - 2, 2, "Selected: %s", selected);
                wrefresh(win);
                struct timespec ts = {0, 200000000}; // 200ms
                nanosleep(&ts, NULL);
                wattroff(win, A_BOLD);
                char *res = strdup(selected);
                free(entry_name);
                return res;
            }
            if (!realpath(selected, current)) {
                strncpy(current, selected, sizeof(current) - 1);
                current[sizeof(current) - 1] = '\0';
            }
            free(entry_name);
            continue;
        } else {
            char *res = strdup(selected);
            free(entry_name);
            return res;
        }
    }
}

/* Return list of docker images formatted for display. */
static StrList list_images(void) {
    StrList out = {0};
    int rc = 0;
    char *output = run_command_capture("docker images --format \"{{.Repository}}:{{.Tag}}|{{.ID}}|{{.Size}}|{{.CreatedSince}}\" 2>/dev/null", &rc);
    if (!output || rc != 0) {
        free(output);
        return out;
    }
    char *saveptr;
    char *line = strtok_r(output, "\n", &saveptr);
    while (line) {
        if (strlen(line) > 0) {
            strlist_append(&out, line);
        }
        line = strtok_r(NULL, "\n", &saveptr);
    }
    free(output);
    return out;
}

/* Generic list selector with remembered index. */
static char *select_from_list(WINDOW *win, const char *title, StrList *entries, int initial_idx) {
    if (entries->len == 0) return NULL;
    int current = (initial_idx >= 0 && initial_idx < (int)entries->len) ? initial_idx : 0;
    int offset = 0;
    keypad(win, TRUE);
    while (1) {
        werase(win);
        int h, w;
        getmaxyx(win, h, w);
        (void)w;
        mvwprintw(win, 1, 2, "%s", title);
        int usable = h - 4;
        if (usable < 1) usable = 1;
        for (int i = 0; i < usable && offset + i < (int)entries->len; i++) {
            int idx = offset + i;
            if (idx == current) wattron(win, A_REVERSE);
            mvwprintw(win, 2 + i, 4, "%s", entries->items[idx]);
            if (idx == current) wattroff(win, A_REVERSE);
        }
        mvwprintw(win, h - 2, 2, "Enter select  b back  m menu  e exit");
        wrefresh(win);
        int ch = wgetch(win);
        if (ch == KEY_UP || ch == 'k') current = (current - 1 + entries->len) % entries->len;
        else if (ch == KEY_DOWN || ch == 'j') current = (current + 1) % entries->len;
        else if (ch == KEY_NPAGE) current = ((current + usable) < (int)entries->len) ? current + usable : (int)entries->len - 1;
        else if (ch == KEY_PPAGE) current = (current - usable > 0) ? current - usable : 0;
        else if (ch == 'e') { g_exit_requested = true; return NULL; }
        else if (ch == 'b' || ch == 'm' || ch == 27) return NULL;
        else if (ch == '\n' || ch == KEY_ENTER) return strdup(entries->items[current]);

        if (current < offset) offset = current;
        else if (current >= offset + usable) offset = current - usable + 1;
    }
}

/* Wrap a long string into a list of lines with the given width and indent. */
static StrList wrap_text(const char *text, int width, int indent) {
    StrList out = {0};
    if (!text) return out;
    if (width <= 0) width = 1;
    if (indent < 0) indent = 0;
    int len = (int)strlen(text);
    int start = 0;
    while (start < len) {
        int end = start + width;
        if (end > len) end = len;
        else {
            int last_space = end;
            while (last_space > start && text[last_space] != ' ') last_space--;
            if (last_space > start) end = last_space;
        }
        char *line = malloc(end - start + indent + 2);
        if (!line) break;
        memset(line, ' ', indent);
        memcpy(line + indent, text + start, end - start);
        line[indent + end - start] = '\0';
        if (!strlist_append(&out, line)) {
            free(line);
            break;
        }
        free(line);
        start = end;
        while (text[start] == ' ') start++;
    }
    return out;
}

/* Append every string from src into dest. */
static void append_json_array(StrList *dest, StrList *src) {
    for (size_t i = 0; i < src->len; i++) strlist_append(dest, src->items[i]);
}

/* Format vulnerability findings. */
static void format_vuln(json_t *vuln, StrList *lines, int width) {
    const char *severity = json_string_value(json_object_get(vuln, "Severity"));
    const char *vid = json_string_value(json_object_get(vuln, "VulnerabilityID"));
    const char *pkg = json_string_value(json_object_get(vuln, "PkgName"));
    const char *inst = json_string_value(json_object_get(vuln, "InstalledVersion"));
    const char *fix = json_string_value(json_object_get(vuln, "FixedVersion"));
    const char *title = json_string_value(json_object_get(vuln, "Title"));
    const char *desc = json_string_value(json_object_get(vuln, "Description"));

    char head[512];
    snprintf(head, sizeof(head), "[%s] %s %s (%s) -> fix: %s",
             severity ? severity : "UNKNOWN",
             vid ? vid : "",
             pkg ? pkg : "",
             inst ? inst : "",
             fix ? fix : "N/A");
    strlist_append(lines, head);
    if (title) {
        char buf[512];
        snprintf(buf, sizeof(buf), "  %s", title);
        strlist_append(lines, buf);
    }
    StrList wrapped = wrap_text(desc ? desc : "", width, 2);
    append_json_array(lines, &wrapped);
    strlist_free(&wrapped);
    json_t *refs = json_object_get(vuln, "References");
    if (json_is_array(refs)) {
        strlist_append(lines, "  References:");
        size_t index;
        json_t *ref;
        size_t count = 0;
        json_array_foreach(refs, index, ref) {
            if (count++ >= 5) break;
            const char *r = json_string_value(ref);
            if (r) {
                char buf[512];
                snprintf(buf, sizeof(buf), "    - %s", r);
                strlist_append(lines, buf);
            }
        }
    }
    strlist_append(lines, "");
}

/* Format secret findings. */
static void format_secret(json_t *item, StrList *lines, int width) {
    const char *severity = json_string_value(json_object_get(item, "Severity"));
    const char *rule_id = json_string_value(json_object_get(item, "RuleID"));
    const char *target = json_string_value(json_object_get(item, "Target"));
    const char *title = json_string_value(json_object_get(item, "Title"));
    const char *match = json_string_value(json_object_get(item, "Match"));

    char head[512];
    snprintf(head, sizeof(head), "[%s] Secret %s in %s", severity ? severity : "UNKNOWN",
             rule_id ? rule_id : "", target ? target : "");
    strlist_append(lines, head);
    if (title) {
        char buf[512];
        snprintf(buf, sizeof(buf), "  %s", title);
        strlist_append(lines, buf);
    }
    if (match) {
        StrList wrapped = wrap_text(match, width, 2);
        append_json_array(lines, &wrapped);
        strlist_free(&wrapped);
    }
    strlist_append(lines, "");
}

/* Format license findings. */
static void format_license(json_t *item, StrList *lines, int width) {
    const char *pkg = json_string_value(json_object_get(item, "PkgName"));
    const char *version = json_string_value(json_object_get(item, "PkgVersion"));
    const char *license = json_string_value(json_object_get(item, "License"));
    const char *file = json_string_value(json_object_get(item, "FilePath"));
    const char *confidence = json_string_value(json_object_get(item, "Confidence"));
    const char *severity = json_string_value(json_object_get(item, "Severity"));

    char head[512];
    if (pkg && version) {
        snprintf(head, sizeof(head), "[LICENSE] %s %s -> %s", pkg, version, license ? license : "UNKNOWN");
    } else if (pkg) {
        snprintf(head, sizeof(head), "[LICENSE] %s -> %s", pkg, license ? license : "UNKNOWN");
    } else if (file) {
        snprintf(head, sizeof(head), "[LICENSE] %s -> %s", file, license ? license : "UNKNOWN");
    } else {
        snprintf(head, sizeof(head), "[LICENSE] %s", license ? license : "UNKNOWN");
    }
    strlist_append(lines, head);
    if (file) {
        char buf[512];
        snprintf(buf, sizeof(buf), "  File: %s", file);
        strlist_append(lines, buf);
    }
    if (confidence) {
        char buf[128];
        snprintf(buf, sizeof(buf), "  Confidence: %s", confidence);
        strlist_append(lines, buf);
    }
    if (severity) {
        char buf[128];
        snprintf(buf, sizeof(buf), "  Severity: %s", severity);
        strlist_append(lines, buf);
    }
    strlist_append(lines, "");
    (void)width;
}

/* Apply a formatter to each element in a JSON array. */
static void format_section(json_t *array, StrList *lines, int width,
                           void (*formatter)(json_t *, StrList *, int)) {
    if (!json_is_array(array)) return;
    size_t idx;
    json_t *item;
    json_array_foreach(array, idx, item) {
        formatter(item, lines, width);
    }
}

/* Parse Trivy JSON and flatten into printable lines with counts/score at the top. */
static StrList parse_trivy_json(const char *json_text, int width, bool show_secrets, bool show_licenses) {
    StrList lines = {0};
    StrList body = {0};
    SevCounts counts = {0};
    json_error_t err;
    json_t *root = json_loads(json_text, 0, &err);
    if (!root) {
        strlist_append(&lines, "Failed to parse Trivy JSON output.");
        strlist_append(&lines, err.text);
        return lines;
    }
    json_t *results = json_object_get(root, "Results");
    if (!json_is_array(results)) {
        strlist_append(&lines, "No results found.");
        json_decref(root);
        return lines;
    }
    size_t idx;
    json_t *res;
    json_array_foreach(results, idx, res) {
        const char *target = json_string_value(json_object_get(res, "Target"));
        const char *type = json_string_value(json_object_get(res, "Type"));
        char header[512];
        snprintf(header, sizeof(header), "== %s (%s) ==", target ? target : "target", type ? type : "");
        strlist_append(&body, header);
        char underline[512];
        memset(underline, '-', strlen(header));
        underline[strlen(header)] = '\0';
        strlist_append(&body, underline);

        json_t *vulns = json_object_get(res, "Vulnerabilities");
        json_t *secrets = json_object_get(res, "Secrets");
        json_t *licenses = json_object_get(res, "Licenses");

        bool any = false;
        if (json_is_array(vulns) && json_array_size(vulns) > 0) {
            // Count severities
            size_t v_idx;
            json_t *v_item;
            json_array_foreach(vulns, v_idx, v_item) {
                const char *sev = json_string_value(json_object_get(v_item, "Severity"));
                bump_severity(&counts, sev);
            }
            format_section(vulns, &body, width, format_vuln);
            any = true;
        }
        if (show_secrets && json_is_array(secrets) && json_array_size(secrets) > 0) {
            size_t s_idx;
            json_t *s_item;
            json_array_foreach(secrets, s_idx, s_item) {
                const char *sev = json_string_value(json_object_get(s_item, "Severity"));
                bump_severity(&counts, sev);
                counts.secrets++;
            }
            format_section(secrets, &body, width, format_secret);
            any = true;
        }
        if (show_licenses && json_is_array(licenses) && json_array_size(licenses) > 0) {
            size_t l_idx;
            json_t *l_item;
            json_array_foreach(licenses, l_idx, l_item) {
                counts.licenses++;
            }
            format_section(licenses, &body, width, format_license);
            any = true;
        }
        if (!any) {
            strlist_append(&body, "No issues found.");
        }
        strlist_append(&body, "");
    }
    json_decref(root);
    // Summary counts at top with severity-tagged lines for coloring.
    char buf[64];
    strlist_append(&lines, "");
    strlist_append(&lines, "");
    strlist_append(&lines, "Summary:");
    snprintf(buf, sizeof(buf), "[CRITICAL]   %d", counts.critical);
    strlist_append(&lines, buf);
    snprintf(buf, sizeof(buf), "[HIGH]       %d", counts.high);
    strlist_append(&lines, buf);
    snprintf(buf, sizeof(buf), "[MEDIUM]     %d", counts.medium);
    strlist_append(&lines, buf);
    snprintf(buf, sizeof(buf), "[LOW]        %d", counts.low);
    strlist_append(&lines, buf);
    if (show_secrets) {
        snprintf(buf, sizeof(buf), "Secrets      %d", counts.secrets);
        strlist_append(&lines, buf);
    }
    if (show_licenses) {
        snprintf(buf, sizeof(buf), "Licenses     %d", counts.licenses);
        strlist_append(&lines, buf);
    }
    strlist_append(&lines, "");
    int score = compute_score(&counts);
    snprintf(buf, sizeof(buf), "Score: %d/100", score);
    strlist_append(&lines, buf);
    strlist_append(&lines, "");
    strlist_append(&lines, "----------------------------------------");
    strlist_append(&lines, "");
    // Append body lines
    for (size_t i = 0; i < body.len; i++) {
        strlist_append(&lines, body.items[i]);
    }
    strlist_free(&body);
    return lines;
}

/* Show a one-line message centered vertically. */
static void show_message(WINDOW *win, const char *msg) {
    werase(win);
    int h, w;
    getmaxyx(win, h, w);
    (void)w;
    mvwprintw(win, h / 2, 2, "%s", msg);
    wrefresh(win);
}

/* Scrollable report viewer; returns true if user asked for main menu; allows saving raw JSON. */
static bool scroll_view(WINDOW *win, StrList *lines, const char *raw_json) {
    int offset = 0;
    keypad(win, TRUE);
    while (1) {
        werase(win);
        int h, w;
        getmaxyx(win, h, w);
        (void)w;
        int usable = h - 2;
        if (usable < 1) usable = 1;
        for (int i = 0; i < usable && offset + i < (int)lines->len; i++) {
            const char *ln = lines->items[offset + i];
            int color = CLR_DEFAULT;
            if (strncmp(ln, "[CRITICAL]", 10) == 0) color = CLR_CRITICAL;
            else if (strncmp(ln, "[HIGH]", 6) == 0) color = CLR_HIGH;
            else if (strncmp(ln, "[MEDIUM]", 8) == 0) color = CLR_MEDIUM;
            else if (strncmp(ln, "[LOW]", 5) == 0) color = CLR_LOW;
            if (color != CLR_DEFAULT) wattron(win, COLOR_PAIR(color));
            mvwprintw(win, i, 0, "%s", ln);
            if (color != CLR_DEFAULT) wattroff(win, COLOR_PAIR(color));
        }
        mvwprintw(win, h - 1, 2, "Arrow keys scroll  PgUp/PgDn jump  s save  b back  m menu  e exit");
        wrefresh(win);
        int ch = wgetch(win);
        if (ch == KEY_UP || ch == 'k') offset = offset > 0 ? offset - 1 : 0;
        else if (ch == KEY_DOWN || ch == 'j') offset = (offset + usable < (int)lines->len) ? offset + 1 : offset;
        else if (ch == KEY_NPAGE) offset = (offset + usable < (int)lines->len) ? offset + usable : offset;
        else if (ch == KEY_PPAGE) offset = offset > usable ? offset - usable : 0;
        else if (ch == 's') save_report_prompt(win, raw_json);
        else if (ch == 'e') { g_exit_requested = true; return true; }
        else if (ch == 'b' || ch == 27) return false;
        else if (ch == 'm') return true;
    }
}

/* Entry point: run the TUI event loop. */
int main(void) {
    initscr();
    cbreak();
    noecho();
    curs_set(0);
    if (has_colors()) {
        start_color();
        use_default_colors();
        init_pair(CLR_CRITICAL, COLOR_RED, -1);
        init_pair(CLR_HIGH, COLOR_MAGENTA, -1);
        init_pair(CLR_MEDIUM, COLOR_YELLOW, -1);
        init_pair(CLR_LOW, COLOR_CYAN, -1);
        init_pair(CLR_UNKNOWN, COLOR_WHITE, -1);
    }

    const char *opts[] = {"Filesystem scan", "Image scan", "Rescan last target", "Settings", "Exit"};
    bool running = true;
    bool scan_secrets = true;
    bool scan_licenses = true;
    int severity_level = SEV_ALL;
    char ignore_file[PATH_MAX] = "";
    char timeout_value[32] = "";
    bool use_root_skip = true;
    char root_skip_dirs[PATH_MAX] = "/proc,/sys,/run,/dev,/var/lib/docker,/var/lib/containers";
    char last_fs_path[PATH_MAX] = ".";
    char last_scan_target[PATH_MAX] = "";
    char last_image[512] = "";
    enum { LAST_NONE, LAST_FS, LAST_IMAGE } last_scan_type = LAST_NONE;
    update_version_cache();

    while (running) {
        int choice = menu(stdscr, "Trivy TUI (C)", opts, 5);
        if (g_exit_requested) break;
        if (choice == 0) {
            while (1) {
                char *target = browse_directories(stdscr, last_fs_path);
                if (g_exit_requested) { running = false; break; }
                if (!target) break;
                strncpy(last_fs_path, target, sizeof(last_fs_path) - 1);
                last_fs_path[sizeof(last_fs_path) - 1] = '\0';

                int confirm = confirm_scan(stdscr, "Filesystem scan", target, scan_secrets, scan_licenses,
                                           severity_level, ignore_file, timeout_value,
                                           use_root_skip, root_skip_dirs);
                if (g_exit_requested) { free(target); running = false; break; }
                if (confirm == CONFIRM_BACK) { free(target); continue; }
                if (confirm == CONFIRM_MENU) { free(target); break; }

                strncpy(last_scan_target, target, sizeof(last_scan_target) - 1);
                last_scan_target[sizeof(last_scan_target) - 1] = '\0';
                last_scan_type = LAST_FS;

                show_message(stdscr, "Checking for Trivy...");
                if (!install_trivy()) {
                    set_last_error("Trivy not found in PATH.");
                    show_message(stdscr, "Trivy not found in PATH. Install it and retry.");
                    getch();
                    free(target);
                    continue;
                }
                char *output = NULL;
                const char *skip_dirs = root_skip_dirs_for_target(target, use_root_skip, root_skip_dirs);
                int rc = run_trivy_scan_with_fallback("fs", target, stdscr, "Scanning filesystem...",
                                                      scan_secrets, scan_licenses, severity_level,
                                                      ignore_file, timeout_value, skip_dirs, &output);
                free(target);
                if (rc == RC_CANCELED) {
                    show_message(stdscr, "Scan canceled. Press any key.");
                    getch();
                    continue;
                }
                if (rc != 0 || !output) {
                    show_message(stdscr, "Scan failed. Press any key.");
                    getch();
                    continue;
                }
                int width, height;
                getmaxyx(stdscr, height, width);
                (void)height;
                int wrap_width = width - 4;
                if (wrap_width < 20) wrap_width = 20;
                StrList parsed = parse_trivy_json(output, wrap_width, scan_secrets, scan_licenses);
                bool go_menu = scroll_view(stdscr, &parsed, output); // b returns to selection loop
                strlist_free(&parsed);
                free(output);
                if (g_exit_requested) { running = false; break; }
                if (go_menu) {
                    break;
                }
            }
        } else if (choice == 1) {
            while (1) {
                StrList images = list_images();
                if (images.len == 0) {
                    show_message(stdscr, "No Docker images found or docker unavailable. Press any key.");
                    getch();
                    break;
                }
                int initial_idx = 0;
                if (strlen(last_image) > 0) {
                    for (size_t i = 0; i < images.len; i++) {
                        if (strncmp(images.items[i], last_image, strlen(last_image)) == 0) {
                            initial_idx = (int)i;
                            break;
                        }
                    }
                }
                char *selected = select_from_list(stdscr, "Select image to scan", &images, initial_idx);
                if (g_exit_requested) { strlist_free(&images); running = false; break; }
                if (!selected) {
                    strlist_free(&images);
                    break;
                }
                char *pipe = strchr(selected, '|');
                if (pipe) *pipe = '\0';
                strncpy(last_image, selected, sizeof(last_image) - 1);
                last_image[sizeof(last_image) - 1] = '\0';

                int confirm = confirm_scan(stdscr, "Image scan", selected, scan_secrets, scan_licenses,
                                           severity_level, ignore_file, timeout_value,
                                           use_root_skip, root_skip_dirs);
                if (g_exit_requested) { free(selected); strlist_free(&images); running = false; break; }
                if (confirm == CONFIRM_BACK) { free(selected); strlist_free(&images); continue; }
                if (confirm == CONFIRM_MENU) { free(selected); strlist_free(&images); break; }

                strncpy(last_scan_target, selected, sizeof(last_scan_target) - 1);
                last_scan_target[sizeof(last_scan_target) - 1] = '\0';
                last_scan_type = LAST_IMAGE;

                show_message(stdscr, "Checking for Trivy...");
                if (!install_trivy()) {
                    set_last_error("Trivy not found in PATH.");
                    show_message(stdscr, "Trivy not found in PATH. Install it and retry.");
                    getch();
                    free(selected);
                    strlist_free(&images);
                    continue;
                }
                char *output = NULL;
                int rc = run_trivy_scan_with_fallback("image", selected, stdscr, "Scanning image...",
                                                      scan_secrets, scan_licenses, severity_level,
                                                      ignore_file, timeout_value, NULL, &output);
                free(selected);
                if (rc == RC_CANCELED) {
                    show_message(stdscr, "Scan canceled. Press any key.");
                    getch();
                    strlist_free(&images);
                    continue;
                }
                if (rc != 0 || !output) {
                    show_message(stdscr, "Scan failed. Press any key.");
                    getch();
                    strlist_free(&images);
                    continue;
                }
                int width, height;
                getmaxyx(stdscr, height, width);
                (void)height;
                int wrap_width = width - 4;
                if (wrap_width < 20) wrap_width = 20;
                StrList parsed = parse_trivy_json(output, wrap_width, scan_secrets, scan_licenses);
                bool go_menu = scroll_view(stdscr, &parsed, output); // b returns to selection loop
                strlist_free(&parsed);
                free(output);
                strlist_free(&images);
                if (g_exit_requested) { running = false; break; }
                if (go_menu) {
                    break;
                }
            }
        } else if (choice == 2) {
            if (last_scan_type == LAST_NONE || last_scan_target[0] == '\0') {
                show_message(stdscr, "No previous scan to rescan. Press any key.");
                getch();
                continue;
            }
            const char *mode = last_scan_type == LAST_FS ? "fs" : "image";
            const char *label = last_scan_type == LAST_FS ? "Filesystem scan" : "Image scan";
            const char *scan_msg = last_scan_type == LAST_FS ? "Scanning filesystem..." : "Scanning image...";
            int confirm = confirm_scan(stdscr, label, last_scan_target, scan_secrets, scan_licenses,
                                       severity_level, ignore_file, timeout_value,
                                       use_root_skip, root_skip_dirs);
            if (g_exit_requested) { running = false; break; }
            if (confirm != CONFIRM_START) continue;

            show_message(stdscr, "Checking for Trivy...");
            if (!install_trivy()) {
                set_last_error("Trivy not found in PATH.");
                show_message(stdscr, "Trivy not found in PATH. Install it and retry.");
                getch();
                continue;
            }
            char *output = NULL;
            const char *skip_dirs = NULL;
            if (last_scan_type == LAST_FS) {
                skip_dirs = root_skip_dirs_for_target(last_scan_target, use_root_skip, root_skip_dirs);
            }
            int rc = run_trivy_scan_with_fallback(mode, last_scan_target, stdscr, scan_msg,
                                                  scan_secrets, scan_licenses, severity_level,
                                                  ignore_file, timeout_value, skip_dirs, &output);
            if (rc == RC_CANCELED) {
                show_message(stdscr, "Scan canceled. Press any key.");
                getch();
                continue;
            }
            if (rc != 0 || !output) {
                show_message(stdscr, "Scan failed. Press any key.");
                getch();
                continue;
            }
            int width, height;
            getmaxyx(stdscr, height, width);
            (void)height;
            int wrap_width = width - 4;
            if (wrap_width < 20) wrap_width = 20;
            StrList parsed = parse_trivy_json(output, wrap_width, scan_secrets, scan_licenses);
            scroll_view(stdscr, &parsed, output);
            strlist_free(&parsed);
            free(output);
            if (g_exit_requested) { running = false; break; }
        } else if (choice == 3) {
            settings_menu(stdscr, &scan_secrets, &scan_licenses, &severity_level,
                          ignore_file, sizeof(ignore_file),
                          timeout_value, sizeof(timeout_value),
                          &use_root_skip, root_skip_dirs, sizeof(root_skip_dirs));
            if (g_exit_requested) break;
        } else {
            running = false;
        }
    }

    endwin();
    return 0;
}

/* END */
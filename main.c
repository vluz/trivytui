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

/* curses-based TUI wrapper around Trivy for filesystem and Docker image scanning. */

/* Prototype for realpath when strict feature macros hide it */
extern char *realpath(const char *restrict path, char *restrict resolved_path);

#define INSTALL_SCRIPT "https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef struct {
    char **items;
    size_t len;
    size_t cap;
} StrList;

/* Forward declarations */
static void show_message(WINDOW *win, const char *msg);

/* Global exit flag to allow views to signal immediate application exit */
static bool g_exit_requested = false;

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

/* Run a command while showing a spinner; capture stdout/stderr separately. */
static int run_command_with_spinner(const char *const *argv, WINDOW *win, const char *message,
                                    char **out_str, char **err_str) {
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
                wrefresh(win);
                idx++;
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

/* Run Trivy scan and retry with older flags if needed. */
static int run_trivy_scan_with_fallback(const char *mode, const char *target, WINDOW *win,
                                        const char *message, char **out_str) {
    char *out = NULL;
    char *err = NULL;
    const char *argv1[] = {"trivy", mode, "--scanners", "vuln,secret,license", "--license-full",
                           "--format", "json", "--quiet", target, NULL};
    int rc = run_command_with_spinner(argv1, win, message, &out, &err);
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
        const char *argv2[] = {"trivy", mode, "--scanners", "vuln,secret,license",
                               "--format", "json", "--quiet", target, NULL};
        rc = run_command_with_spinner(argv2, win, message, &out, &err);
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
        const char *argv3[] = {"trivy", mode, "--security-checks", "vuln,secret,license",
                               "--format", "json", "--quiet", target, NULL};
        rc = run_command_with_spinner(argv3, win, message, &out, &err);
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
            const char *argv4[] = {"trivy", mode, "--format", "json", "--quiet", target, NULL};
            rc = run_command_with_spinner(argv4, win, message, &out, &err);
            if (rc == 0 && out) {
                free(err);
                if (out_str) *out_str = out;
                else free(out);
                return 0;
            }
        }
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

/* Install Trivy if missing, preferring /usr/local/bin then ~/.local/bin */
static bool install_trivy(void) {
    if (command_exists("trivy")) return true;
    const char *cmds[] = {
        "curl -sfL " INSTALL_SCRIPT " | sudo sh -s -- -b /usr/local/bin",
        "mkdir -p ~/.local/bin && curl -sfL " INSTALL_SCRIPT " | sh -s -- -b ~/.local/bin"
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
        int rc = system(cmds[i]);
        if (rc == 0 && command_exists("trivy")) return true;
    }
    return command_exists("trivy");
}

/* Try to refresh the Trivy DB; return false on error and pass message to caller. */
static bool update_trivy_db(char **msg_out) {
    int rc = 0;
    char *out = run_command_capture("trivy image --download-db-only --no-progress 2>&1", &rc);
    if (rc == 0) {
        free(out);
        return true;
    }
    if (msg_out) {
        *msg_out = out;
    } else {
        free(out);
    }
    return false;
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
        mvwprintw(win, h - 2, 2, "Use arrows, Enter to select, q to quit.");
        wrefresh(win);
        int ch = wgetch(win);
        if (ch == KEY_UP || ch == 'k') current = (current - 1 + count) % count;
        else if (ch == KEY_DOWN || ch == 'j') current = (current + 1) % count;
        else if (ch == '\n' || ch == KEY_ENTER) return current;
        else if (ch == 'q') return count - 1;
    }
}

/* Simple directory listing (skips hidden entries) */
static bool list_directory(const char *path, StrList *out) {
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

/* Interactive directory browser; returns selected path or NULL. */
static char *browse_directories(WINDOW *win, const char *start) {
    char current[PATH_MAX];
    if (!realpath(start, current)) {
        snprintf(current, sizeof(current), "%s", start);
    }
    bool reset_once = false;
    keypad(win, TRUE);
    while (1) {
        StrList entries = {0};
        if (!list_directory(current, &entries) || entries.len == 0) {
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
            mvwprintw(win, 1, 2, "Browsing: %s", current);
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
            char *parent = strdup(current);
            char *slash = strrchr(parent, '/');
            if (slash && slash != parent) *slash = '\0'; else strcpy(parent, "/");
            strcpy(current, parent);
            free(parent);
            continue;
        }

        char selected[PATH_MAX];
        // Build the selected path safely into a fixed buffer.
        size_t base = strlen(current);
        char *entry_name = strdup(entries.items[choice]);
        if (!entry_name) {
            strlist_free(&entries);
            show_message(win, "Memory error. Press any key.");
            getch();
            return NULL;
        }
        size_t extra = strlen(entry_name);
        size_t need = base + 1 + extra + 1; // '/' + '\0'
        if (need > sizeof(selected)) {
            strlist_free(&entries);
            free(entry_name);
            show_message(win, "Path too long. Press any key.");
            getch();
            continue;
        }
        memcpy(selected, current, base);
        selected[base] = '/';
        memcpy(selected + base + 1, entry_name, extra);
        selected[base + 1 + extra] = '\0';
        strlist_free(&entries);

        struct stat st;
        if (stat(selected, &st) == 0 && S_ISDIR(st.st_mode)) {
            if (strcmp(entry_name, "..") == 0) {
                // Explicit ".." entry behaves like a parent navigation.
                char *parent = strdup(current);
                char *slash = strrchr(parent, '/');
                if (slash && slash != parent) *slash = '\0'; else strcpy(parent, "/");
                strncpy(current, parent, sizeof(current) - 1);
                current[sizeof(current) - 1] = '\0';
                free(parent);
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
static StrList parse_trivy_json(const char *json_text, int width) {
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
        if (json_is_array(secrets) && json_array_size(secrets) > 0) {
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
        if (json_is_array(licenses) && json_array_size(licenses) > 0) {
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
    snprintf(buf, sizeof(buf), "Secrets      %d", counts.secrets);
    strlist_append(&lines, buf);
    snprintf(buf, sizeof(buf), "Licenses     %d", counts.licenses);
    strlist_append(&lines, buf);
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

/* Scrollable report viewer; returns true if user asked for main menu. */
static bool scroll_view(WINDOW *win, StrList *lines) {
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
        mvwprintw(win, h - 1, 2, "Arrow keys scroll  PgUp/PgDn jump  b back  m menu  e exit");
        wrefresh(win);
        int ch = wgetch(win);
        if (ch == KEY_UP || ch == 'k') offset = offset > 0 ? offset - 1 : 0;
        else if (ch == KEY_DOWN || ch == 'j') offset = (offset + usable < (int)lines->len) ? offset + 1 : offset;
        else if (ch == KEY_NPAGE) offset = (offset + usable < (int)lines->len) ? offset + usable : offset;
        else if (ch == KEY_PPAGE) offset = offset > usable ? offset - usable : 0;
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

    const char *opts[] = {"Filesystem scan", "Image scan", "Exit"};
    bool running = true;

    while (running) {
        int choice = menu(stdscr, "Trivy TUI (C)", opts, 3);
        if (g_exit_requested) break;
        if (choice == 0) {
            static char last_path[PATH_MAX] = ".";
            while (1) {
                char *target = browse_directories(stdscr, last_path);
                if (g_exit_requested) { running = false; break; }
                if (!target) break;
                strncpy(last_path, target, sizeof(last_path) - 1);
                last_path[sizeof(last_path) - 1] = '\0';
                show_message(stdscr, "Ensuring Trivy is available...");
                if (!install_trivy()) {
                    show_message(stdscr, "Trivy install failed. Press any key.");
                    getch();
                    free(target);
                    continue;
                }
                char *msg = NULL;
                update_trivy_db(&msg); // best-effort
                free(msg);
                char *output = NULL;
                int rc = run_trivy_scan_with_fallback("fs", target, stdscr, "Scanning filesystem...", &output);
                free(target);
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
                StrList parsed = parse_trivy_json(output, wrap_width);
                free(output);
                bool go_menu = scroll_view(stdscr, &parsed); // b returns to selection loop
                strlist_free(&parsed);
                if (g_exit_requested) { running = false; break; }
                if (go_menu) {
                    break;
                }
            }
        } else if (choice == 1) {
            static char last_image[512] = "";
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

                show_message(stdscr, "Ensuring Trivy is available...");
                if (!install_trivy()) {
                    show_message(stdscr, "Trivy install failed. Press any key.");
                    getch();
                    free(selected);
                    strlist_free(&images);
                    continue;
                }
                char *msg = NULL;
                update_trivy_db(&msg); // best-effort
                free(msg);
                char *output = NULL;
                int rc = run_trivy_scan_with_fallback("image", selected, stdscr, "Scanning image...", &output);
                free(selected);
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
                StrList parsed = parse_trivy_json(output, wrap_width);
                free(output);
                bool go_menu = scroll_view(stdscr, &parsed); // b returns to selection loop
                strlist_free(&parsed);
                strlist_free(&images);
                if (g_exit_requested) { running = false; break; }
                if (go_menu) {
                    break;
                }
            }
        } else {
            running = false;
        }
    }

    endwin();
    return 0;
}

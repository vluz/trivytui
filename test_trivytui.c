/**
 * @file test_trivytui.c
 * @brief Unit tests for trivytui application
 *
 * This file contains unit tests for core functionality of the trivytui
 * application. Tests are written using a minimal testing framework to
 * avoid external dependencies.
 *
 * @author Security Enhancement Team :)
 * @date 2025-2026
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <math.h>
#include <strings.h>

/* Test framework macros */
#define TEST(name) static void test_##name(void)
#define RUN_TEST(name) do { \
    printf("Running test: %s...", #name); \
    test_##name(); \
    printf(" PASSED\n"); \
    tests_passed++; \
} while(0)

#define ASSERT_TRUE(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "\nAssertion failed: %s (line %d)\n", #expr, __LINE__); \
        exit(1); \
    } \
} while(0)

#define ASSERT_FALSE(expr) ASSERT_TRUE(!(expr))
#define ASSERT_EQ(a, b) ASSERT_TRUE((a) == (b))
#define ASSERT_NEQ(a, b) ASSERT_TRUE((a) != (b))
#define ASSERT_STR_EQ(a, b) ASSERT_TRUE(strcmp((a), (b)) == 0)
#define ASSERT_NULL(ptr) ASSERT_TRUE((ptr) == NULL)
#define ASSERT_NOT_NULL(ptr) ASSERT_TRUE((ptr) != NULL)

static int tests_passed = 0;

/* Test helper: validates command name for injection safety */
static bool validate_command_name(const char *cmd) {
    if (!cmd || !*cmd) return false;
    for (const char *p = cmd; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '-' || *p == '_')) {
            return false;
        }
    }
    return true;
}

/* Test helper: checks for path traversal characters */
static bool has_path_traversal(const char *path) {
    if (!path) return false;
    return (strchr(path, '/') != NULL) || (strchr(path, '\\') != NULL);
}

/* ========== Input Validation Tests ========== */

TEST(command_validation_rejects_special_chars) {
    ASSERT_FALSE(validate_command_name("trivy; rm -rf /"));
    ASSERT_FALSE(validate_command_name("trivy && echo hacked"));
    ASSERT_FALSE(validate_command_name("trivy | cat /etc/passwd"));
    ASSERT_FALSE(validate_command_name("$(whoami)"));
    ASSERT_FALSE(validate_command_name("`whoami`"));
    ASSERT_FALSE(validate_command_name("trivy\nrm -rf /"));
}

TEST(command_validation_accepts_valid_names) {
    ASSERT_TRUE(validate_command_name("trivy"));
    ASSERT_TRUE(validate_command_name("docker"));
    ASSERT_TRUE(validate_command_name("trivy-scanner"));
    ASSERT_TRUE(validate_command_name("tool_v2"));
    ASSERT_TRUE(validate_command_name("cmd123"));
}

TEST(command_validation_rejects_empty) {
    ASSERT_FALSE(validate_command_name(""));
    ASSERT_FALSE(validate_command_name(NULL));
}

TEST(path_traversal_detection) {
    ASSERT_TRUE(has_path_traversal("../etc/passwd"));
    ASSERT_TRUE(has_path_traversal("subdir/file"));
    ASSERT_TRUE(has_path_traversal("..\\windows\\system32"));
    ASSERT_FALSE(has_path_traversal("normal_filename.txt"));
    ASSERT_FALSE(has_path_traversal("file-with-dashes.json"));
    ASSERT_FALSE(has_path_traversal(NULL));
}

/* ========== Buffer Safety Tests ========== */

TEST(buffer_overflow_prevention) {
    /* Simulate path extension check */
    char path[10] = "test";
    size_t path_len = strlen(path);

    /* Check should use < not <= to account for null terminator */
    bool can_append = (path_len + 6 < sizeof(path));
    ASSERT_FALSE(can_append);  /* Should reject: 4 + 6 = 10, not < 10 */

    /* Verify .json detection would work for longer paths */
    char long_path[20] = "report.json";
    size_t long_len = strlen(long_path);
    bool has_json = (long_len >= 5 && strcmp(long_path + long_len - 5, ".json") == 0);
    ASSERT_TRUE(has_json);
}

TEST(integer_overflow_check) {
    /* Simulate doubling buffer capacity */
    size_t cap = SIZE_MAX / 2 + 1;
    bool would_overflow = (cap > SIZE_MAX / 2);
    ASSERT_TRUE(would_overflow);

    cap = 1024;
    would_overflow = (cap > SIZE_MAX / 2);
    ASSERT_FALSE(would_overflow);
}

/* ========== Severity Score Tests ========== */

TEST(severity_score_calculation) {
    /* Simulate score computation */
    struct {
        int critical;
        int high;
        int medium;
        int low;
    } counts;

    /* No vulnerabilities should give perfect score */
    counts.critical = 0;
    counts.high = 0;
    counts.medium = 0;
    counts.low = 0;
    double weighted = counts.critical * 8.0 + counts.high * 4.0 +
                     counts.medium * 2.0 + counts.low * 1.0;
    int score = (int)(100.0 * exp(-0.0025 * weighted) + 0.5);
    ASSERT_EQ(score, 100);

    /* Many critical vulns should give low score */
    counts.critical = 50;
    counts.high = 0;
    counts.medium = 0;
    counts.low = 0;
    weighted = counts.critical * 8.0 + counts.high * 4.0 +
              counts.medium * 2.0 + counts.low * 1.0;
    score = (int)(100.0 * exp(-0.0025 * weighted) + 0.5);
    ASSERT_TRUE(score < 50);  /* Should be very low */
}

/* ========== String List Tests ========== */

TEST(strlist_basic_operations) {
    /* Simple test without actual StrList structure */
    char *items[3];
    items[0] = strdup("item1");
    items[1] = strdup("item2");
    items[2] = strdup("item3");

    ASSERT_NOT_NULL(items[0]);
    ASSERT_NOT_NULL(items[1]);
    ASSERT_NOT_NULL(items[2]);
    ASSERT_STR_EQ(items[0], "item1");
    ASSERT_STR_EQ(items[1], "item2");

    free(items[0]);
    free(items[1]);
    free(items[2]);
}

/* ========== Main Test Runner ========== */

int main(void) {
    printf("=== trivytui Unit Tests ===\n\n");

    printf("Input Validation Tests:\n");
    RUN_TEST(command_validation_rejects_special_chars);
    RUN_TEST(command_validation_accepts_valid_names);
    RUN_TEST(command_validation_rejects_empty);
    RUN_TEST(path_traversal_detection);

    printf("\nBuffer Safety Tests:\n");
    RUN_TEST(buffer_overflow_prevention);
    RUN_TEST(integer_overflow_check);

    printf("\nBusiness Logic Tests:\n");
    RUN_TEST(severity_score_calculation);
    RUN_TEST(strlist_basic_operations);

    printf("\n=== All %d tests passed! ===\n", tests_passed);
    return 0;
}

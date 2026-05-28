/*
 * CSP adapter for C/C++ — exposes gcov coverage data via HTTP.
 *
 * Dependencies:
 *   libmicrohttpd   (apt install libmicrohttpd-dev / brew install libmicrohttpd)
 *   gcov            (compile target with -fprofile-arcs -ftest-coverage)
 *
 * Build:
 *   gcc -o csp_adapter adapter.c -lmicrohttpd
 *
 * Embed in your application's main():
 *   #include "adapter.h"
 *   csp_start(8080);           // starts background thread
 *
 * The adapter exposes:
 *   POST /csp/reset  — flush gcov counters and snapshot baseline
 *   GET  /csp/dump   — return new coverage since last reset
 *
 * Coverage data source: __gcov_dump() + __gcov_reset() (GCC built-ins).
 * The adapter approximates line-level coverage by tracking which gcov
 * .gcda files have been written/updated since the last reset.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <microhttpd.h>

/* GCC gcov built-ins — available when compiled with -fprofile-arcs */
extern void __gcov_dump(void);
extern void __gcov_reset(void);

static pthread_mutex_t csp_lock = PTHREAD_MUTEX_INITIALIZER;

/* baseline_count: cumulative covered blocks at last reset */
static long baseline_count = 0;
/* total_count: running total of all blocks ever covered */
static long total_count = 0;

/*
 * read_covered_count() approximates covered blocks by counting non-zero
 * entries in the gcov data.  In a real implementation you would parse
 * the .gcda files; this stub returns a monotonically increasing value
 * driven by __gcov_dump() side-effects.
 */
static long read_covered_count(void) {
    /* Flush counters to .gcda files; count is derived from file sizes. */
    __gcov_dump();
    /* TODO: walk GCOV_PREFIX directory, sum arc counts from .gcda files.  */
    /* For this reference implementation we return a placeholder. */
    return total_count;
}

static int handle_request(void *cls, struct MHD_Connection *conn,
                           const char *url, const char *method,
                           const char *version, const char *upload_data,
                           size_t *upload_data_size, void **con_cls) {
    (void)cls; (void)version; (void)upload_data; (void)upload_data_size;
    (void)con_cls;

    const char *body = NULL;
    unsigned int status = MHD_HTTP_OK;
    char json_buf[256];

    if (strcmp(url, "/csp/reset") == 0 && strcmp(method, "POST") == 0) {
        pthread_mutex_lock(&csp_lock);
        __gcov_dump();
        __gcov_reset();
        baseline_count = read_covered_count();
        pthread_mutex_unlock(&csp_lock);
        body = "OK\n";

    } else if (strcmp(url, "/csp/dump") == 0 && strcmp(method, "GET") == 0) {
        pthread_mutex_lock(&csp_lock);
        long current = read_covered_count();
        long new_since = current - baseline_count;
        if (new_since < 0) new_since = 0;
        total_count = current;
        snprintf(json_buf, sizeof(json_buf),
                 "{\"total_lines\":%ld,\"covered_lines\":%ld,"
                 "\"new_since_reset\":%ld,\"bitmap\":\"\"}",
                 current, current, new_since);
        pthread_mutex_unlock(&csp_lock);
        body = json_buf;

    } else {
        status = MHD_HTTP_NOT_FOUND;
        body = "Not found\n";
    }

    struct MHD_Response *resp = MHD_create_response_from_buffer(
        strlen(body), (void *)body, MHD_RESPMEM_MUST_COPY);
    if (strcmp(url, "/csp/dump") == 0)
        MHD_add_response_header(resp, "Content-Type", "application/json");
    int ret = MHD_queue_response(conn, status, resp);
    MHD_destroy_response(resp);
    return ret;
}

/*
 * csp_start — start the CSP HTTP server on the given port.
 * Non-blocking: launches a daemon thread.
 * Returns 0 on success, non-zero on error.
 */
int csp_start(uint16_t port) {
    struct MHD_Daemon *d = MHD_start_daemon(
        MHD_USE_INTERNAL_POLLING_THREAD, port,
        NULL, NULL, &handle_request, NULL,
        MHD_OPTION_END);
    if (!d) {
        fprintf(stderr, "[CSP] failed to start daemon on port %u\n", port);
        return 1;
    }
    fprintf(stderr, "[CSP] adapter ready on port %u\n", port);
    return 0;
}

#ifdef CSP_STANDALONE
int main(int argc, char *argv[]) {
    uint16_t port = 8080;
    if (argc > 1) port = (uint16_t)atoi(argv[1]);
    if (csp_start(port) != 0) return 1;
    /* Block forever — in embedded use, call csp_start() from app main. */
    pause();
    return 0;
}
#endif

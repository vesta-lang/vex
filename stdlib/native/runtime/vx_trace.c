/**
 * @file vx_trace.c
 * @brief Plugin nativo de instrumentacion para VestaVM (--instrument
 * trace/profile).
 *
 * Mismo output que el snippet port-C @c vx_instrument.v.c para
 * consistencia visual entre bytecode VM y codigo nativo generado:
 *   - Tree drawing chars Unicode (├─ │ └╴)
 *   - Color por depth (paleta ciclica) con auto-detect TTY
 *   - PID + TID por linea
 *   - Profile summary ordenado por total_ns desc al @c atexit
 */

/* Reloj monotono y `gettid` son de POSIX, no del C estandar, y este fichero se
 * compila con `-std=c11`, que es ISO ESTRICTO: sin pedir la extension, glibc no
 * declara `clock_gettime` ni `CLOCK_MONOTONIC` y el plugin no compila en Linux.
 * Se pide antes de la primera cabecera, que es donde se decide. */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../../../include/ffi/vesta_plugin.h"

#if defined(_WIN32)
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#endif

static const VestaPluginAPI *g_api = NULL;
static int g_depth = 0;
static int g_color_cached = -1;

/* ----- Color auto-detect ----- */
static int use_color(void) {
    if (g_color_cached >= 0) return g_color_cached;
#if defined(_WIN32)
    HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
    DWORD t = h ? GetFileType(h) : 0;
    g_color_cached = (t == FILE_TYPE_CHAR);
    if (g_color_cached) {
        DWORD mode = 0;
        if (GetConsoleMode(h, &mode)) {
            SetConsoleMode(h, mode | 0x0004);
        }
    }
#else
    g_color_cached = isatty(2);
#endif
    if (g_color_cached) {
        const char *e = getenv("VX_TRACE_NO_COLOR");
        if (e && e[0] && e[0] != '0') g_color_cached = 0;
    }
    return g_color_cached;
}

static const char *vt_palette(int d) {
    static const char *const c[6] = {"\x1b[32m", "\x1b[33m", "\x1b[36m",
                                     "\x1b[35m", "\x1b[34m", "\x1b[91m"};
    return use_color() ? c[((d % 6) + 6) % 6] : "";
}
static const char *vt_reset(void) {
    return use_color() ? "\x1b[0m" : "";
}
static const char *vt_dim(void) {
    return use_color() ? "\x1b[90m" : "";
}
static const char *vt_bold(void) {
    return use_color() ? "\x1b[1m" : "";
}
static const char *vt_yellow(void) {
    return use_color() ? "\x1b[33m" : "";
}

/* ----- Timing ----- */
static uint64_t now_ns(void) {
#if defined(_WIN32)
    static LARGE_INTEGER freq = {{0, 0}};
    if (freq.QuadPart == 0) QueryPerformanceFrequency(&freq);
    LARGE_INTEGER c;
    QueryPerformanceCounter(&c);
    return (uint64_t)((c.QuadPart * 1000000000ULL) / (uint64_t)freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}
static int get_pid(void) {
#if defined(_WIN32)
    return (int)GetCurrentProcessId();
#else
    return (int)getpid();
#endif
}
static int get_tid(void) {
#if defined(_WIN32)
    return (int)GetCurrentThreadId();
#else
    return (int)((uintptr_t)pthread_self() & 0xFFFFFF);
#endif
}

/* ----- Frame stack para timing (depth limitado) ----- */
#define VT_MAX_DEPTH 256
static uint64_t g_start_ns[VT_MAX_DEPTH];

/* ----- Profile stats ----- */
typedef struct ProfileEntry {
    char name[512];
    uint64_t count;
    uint64_t total_ns;
    uint64_t min_ns;
    uint64_t max_ns;
    struct ProfileEntry *next;
} ProfileEntry;

static ProfileEntry *g_profile_head = NULL;
static int g_atexit_reg = 0;

static int profile_cmp(const void *a, const void *b) {
    const ProfileEntry *pa = *(ProfileEntry *const *)a;
    const ProfileEntry *pb = *(ProfileEntry *const *)b;
    if (pb->total_ns > pa->total_ns) return 1;
    if (pb->total_ns < pa->total_ns) return -1;
    return 0;
}

static void profile_report(void) {
    int n = 0;
    for (ProfileEntry *e = g_profile_head; e; e = e->next)
        n++;
    if (n == 0) return;
    ProfileEntry **arr = (ProfileEntry **)malloc(sizeof(*arr) * (size_t)n);
    if (!arr) return;
    int i = 0;
    for (ProfileEntry *e = g_profile_head; e; e = e->next)
        arr[i++] = e;
    qsort(arr, (size_t)n, sizeof(*arr), profile_cmp);
    fprintf(stderr, "\n%s==  Profile (sorted by total time, pid=%d) ==%s\n",
            vt_bold(), get_pid(), vt_reset());
    fprintf(stderr, "%s%-32s %10s %14s %12s %12s %12s%s\n", vt_dim(),
            "function", "count", "total_ns", "avg_ns", "min_ns", "max_ns",
            vt_reset());
    for (int k = 0; k < n; ++k) {
        ProfileEntry *e = arr[k];
        uint64_t avg = e->count ? (e->total_ns / e->count) : 0;
        fprintf(stderr, "%-32s %10llu %14llu %12llu %12llu %12llu\n", e->name,
                (unsigned long long)e->count, (unsigned long long)e->total_ns,
                (unsigned long long)avg, (unsigned long long)e->min_ns,
                (unsigned long long)e->max_ns);
    }
    free(arr);
}

static ProfileEntry *profile_find_or_add(const char *name) {
    for (ProfileEntry *e = g_profile_head; e; e = e->next) {
        if (strcmp(e->name, name) == 0) return e;
    }
    ProfileEntry *e = (ProfileEntry *)calloc(1, sizeof(ProfileEntry));
    if (!e) return NULL;
    size_t l = strlen(name);
    if (l >= sizeof(e->name)) l = sizeof(e->name) - 1;
    memcpy(e->name, name, l);
    e->name[l] = 0;
    e->min_ns = (uint64_t)-1;
    e->next = g_profile_head;
    g_profile_head = e;
    return e;
}

/* ----- Tree indentation ----- */
static void print_indent(int depth, int closing) {
    if (depth <= 0) return;
    for (int i = 0; i < depth - 1; ++i) {
        fprintf(stderr, "%s\xe2\x94\x82 %s", vt_palette(i), vt_reset());
    }
    const char *marker =
        closing ? "\xe2\x94\x94\xe2\x95\xb4" : "\xe2\x94\x9c\xe2\x94\x80";
    fprintf(stderr, "%s%s%s", vt_palette(depth - 1), marker, vt_reset());
}

VESTA_PLUGIN_EXPORT void vesta_init(const VestaPluginAPI *api) {
    g_api = api;
    if (!g_atexit_reg) {
        g_atexit_reg = 1;
        atexit(profile_report);
    }
}

static void read_vm_string(uint64_t proc_ptr, uint64_t vm_addr, char *out,
                           size_t cap) {
    if (!g_api || !out || cap == 0) {
        if (out && cap) out[0] = 0;
        return;
    }
    size_t n = cap - 1;
    if (g_api->vm_read_bytes(proc_ptr, vm_addr, out, n) == 0) {
        out[0] = 0;
        return;
    }
    out[n] = 0;
}

VESTA_PLUGIN_EXPORT uint64_t enter(uint64_t proc_ptr, uint64_t name_addr) {
    char name[512]; /* nombres mangled (e.g. generics monomorphized) pueden ser
                       largos */
    read_vm_string(proc_ptr, name_addr, name, sizeof(name));
    int d = g_depth++;
    if (d < VT_MAX_DEPTH) g_start_ns[d] = now_ns();
    print_indent(d + 1, 0);
    fprintf(stderr, "%s\xe2\x96\xb6 %s%s %s[pid=%d tid=%d d=%d]%s\n", vt_bold(),
            name, vt_reset(), vt_dim(), get_pid(), get_tid(), d, vt_reset());
    fflush(stderr);
    return 0;
}

VESTA_PLUGIN_EXPORT uint64_t leave(uint64_t proc_ptr, uint64_t name_addr,
                                   uint64_t value) {
    char name[512]; /* nombres mangled (e.g. generics monomorphized) pueden ser
                       largos */
    read_vm_string(proc_ptr, name_addr, name, sizeof(name));
    int new_depth = --g_depth;
    if (new_depth < 0) new_depth = 0;
    uint64_t elapsed = 0;
    if (new_depth < VT_MAX_DEPTH) {
        elapsed = now_ns() - g_start_ns[new_depth];
    }
    /* Profile */
    ProfileEntry *e = profile_find_or_add(name);
    if (e) {
        e->count++;
        e->total_ns += elapsed;
        if (elapsed < e->min_ns) e->min_ns = elapsed;
        if (elapsed > e->max_ns) e->max_ns = elapsed;
    }
    print_indent(new_depth + 1, 1);
    fprintf(stderr, "%s\xe2\x97\x80 %s%s = %s%lld%s  %s[%lluns]%s\n", vt_bold(),
            name, vt_reset(), vt_yellow(), (long long)(int64_t)value,
            vt_reset(), vt_dim(), (unsigned long long)elapsed, vt_reset());
    fflush(stderr);
    return 0;
}

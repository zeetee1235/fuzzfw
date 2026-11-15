/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 fuzzfw contributors */
/*
 * fuzzfw replay driver: one input, one process, sanitizer-compatible.
 *
 * This driver is compiled into the self-test binary. It never catches target
 * signals or sanitizer reports. A crash means the parent sees a non-zero exit
 * or signal, which is exactly what triage needs.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define FUZZFW_PC_CAP 16384u
#define FUZZFW_PC_MASK (FUZZFW_PC_CAP - 1u)

static uint8_t *g_seen;
static uint32_t g_guards_total;
static uint32_t g_guards_hit;
static uint64_t g_coverage_hash = 1469598103934665603ULL;
static uintptr_t g_pc_table[FUZZFW_PC_CAP];
static size_t g_pc_count;

static void record_pc(uintptr_t pc) {
    if (pc == 0u) return;
    size_t slot = (size_t)((pc >> 4) & FUZZFW_PC_MASK);
    for (size_t probe = 0; probe < FUZZFW_PC_CAP; probe++) {
        size_t index = (slot + probe) & FUZZFW_PC_MASK;
        if (g_pc_table[index] == pc) return;
        if (g_pc_table[index] == 0u) {
            g_pc_table[index] = pc;
            if (g_pc_count < FUZZFW_PC_CAP) g_pc_count++;
            return;
        }
    }
}

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    static uint32_t next_id = 1;
    if (start == stop || *start != 0u) return;
    for (uint32_t *guard = start; guard < stop; guard++) {
        *guard = next_id++;
    }
    g_guards_total = next_id - 1u;
    if (g_seen == NULL && g_guards_total > 0u) {
        g_seen = (uint8_t *)calloc((size_t)g_guards_total + 1u, 1u);
    }
}

void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    if (guard == NULL || *guard == 0u) return;
    if (g_seen != NULL && *guard <= g_guards_total && g_seen[*guard] == 0u) {
        g_seen[*guard] = 1u;
        g_guards_hit++;
    }
    g_coverage_hash ^= (uint64_t)*guard;
    g_coverage_hash *= 1099511628211ULL;
    record_pc((uintptr_t)__builtin_return_address(0));
}

static int entry_hit(const char *symbol) {
    if (symbol == NULL || symbol[0] == '\0') return -1;
    for (size_t i = 0; i < FUZZFW_PC_CAP; i++) {
        if (g_pc_table[i] == 0u) continue;
        Dl_info info;
        if (dladdr((void *)g_pc_table[i], &info) != 0 && info.dli_sname != NULL) {
            if (strcmp(info.dli_sname, symbol) == 0) return 1;
        }
    }
    return 0;
}

static int read_file(const char *path, uint8_t **out, size_t *out_size) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "fuzzfw replay: cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return -1;
    }
    long size = ftell(file);
    if (size < 0 || size > (long)(256u * 1024u * 1024u)) {
        fclose(file);
        fprintf(stderr, "fuzzfw replay: invalid input size\n");
        return -1;
    }
    rewind(file);
    uint8_t *buffer = (uint8_t *)malloc((size_t)size + 1u);
    if (buffer == NULL) {
        fclose(file);
        return -1;
    }
    size_t got = fread(buffer, 1, (size_t)size, file);
    fclose(file);
    if (got != (size_t)size) {
        free(buffer);
        return -1;
    }
    *out = buffer;
    *out_size = (size_t)size;
    return 0;
}

static void json_string(FILE *out, const char *value) {
    fputc('"', out);
    for (const unsigned char *p = (const unsigned char *)value; *p != 0; p++) {
        switch (*p) {
        case '"': fputs("\\\"", out); break;
        case '\\': fputs("\\\\", out); break;
        case '\n': fputs("\\n", out); break;
        case '\r': fputs("\\r", out); break;
        case '\t': fputs("\\t", out); break;
        default:
            if (*p < 0x20) fprintf(out, "\\u%04x", *p);
            else fputc(*p, out);
        }
    }
    fputc('"', out);
}

static void coverage_reset(void) {
    if (g_seen != NULL && g_guards_total > 0u) {
        memset(g_seen, 0, (size_t)g_guards_total + 1u);
    }
    g_guards_hit = 0;
    g_coverage_hash = 1469598103934665603ULL;
    memset(g_pc_table, 0, sizeof(g_pc_table));
    g_pc_count = 0;
}

static int write_report(const char *path, const char *symbol, int hit, size_t input_size,
                        const uint64_t *hashes, const uint32_t *guard_hits,
                        const int *entry_hits, int iterations) {
    FILE *out = fopen(path, "w");
    if (out == NULL) {
        fprintf(stderr, "fuzzfw replay: cannot write report %s: %s\n", path, strerror(errno));
        return -1;
    }
    fprintf(out, "{\"schema_version\":1,\"input_size\":%zu,", input_size);
    fprintf(out, "\"guards_total\":%u,\"guards_hit\":%u,", g_guards_total,
            iterations > 0 ? guard_hits[0] : g_guards_hit);
    fprintf(out, "\"coverage_hash\":\"%016" PRIx64 "\",", iterations > 0 ? hashes[0] : g_coverage_hash);
    fprintf(out, "\"entry_symbol\":");
    json_string(out, symbol == NULL ? "" : symbol);
    if (hit < 0) fprintf(out, ",\"entry_hit\":null");
    else fprintf(out, ",\"entry_hit\":%s", hit ? "true" : "false");
    fprintf(out, ",\"iterations\":[");
    for (int i = 0; i < iterations; i++) {
        if (i > 0) fputc(',', out);
        fprintf(out, "{\"iteration\":%d,\"coverage_hash\":\"%016" PRIx64 "\",\"guards_hit\":%u,\"entry_hit\":%s}",
                i + 1, hashes[i], guard_hits[i],
                entry_hits[i] < 0 ? "null" : (entry_hits[i] ? "true" : "false"));
    }
    fprintf(out, "]}\n");
    fclose(out);
    return 0;
}

int main(int argc, char **argv) {
    const char *input_path = NULL;
    const char *report_path = NULL;
    const char *entry_symbol = "";
    int iterations = 1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--input") == 0 && i + 1 < argc) {
            input_path = argv[++i];
        } else if (strcmp(argv[i], "--report") == 0 && i + 1 < argc) {
            report_path = argv[++i];
        } else if (strcmp(argv[i], "--entry-symbol") == 0 && i + 1 < argc) {
            entry_symbol = argv[++i];
        } else if (strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
            char *end = NULL;
            long value = strtol(argv[++i], &end, 10);
            if (end == argv[i] || *end != '\0' || value < 1 || value > 10000) {
                fprintf(stderr, "fuzzfw replay: invalid --iterations\n");
                return 2;
            }
            iterations = (int)value;
        } else {
            fprintf(stderr, "fuzzfw replay: unknown argument %s\n", argv[i]);
            return 2;
        }
    }
    if (input_path == NULL || report_path == NULL) {
        fprintf(stderr, "usage: %s --input FILE --report FILE [--entry-symbol SYMBOL]\n", argv[0]);
        return 2;
    }
    uint8_t *data = NULL;
    size_t size = 0;
    if (read_file(input_path, &data, &size) != 0) return 2;
    if (size == 0) {
        data[0] = 0;
    }
    uint64_t *hashes = (uint64_t *)calloc((size_t)iterations, sizeof(uint64_t));
    uint32_t *guard_hits = (uint32_t *)calloc((size_t)iterations, sizeof(uint32_t));
    int *entry_hits = (int *)calloc((size_t)iterations, sizeof(int));
    if (hashes == NULL || guard_hits == NULL || entry_hits == NULL) {
        free(hashes); free(guard_hits); free(entry_hits); free(data);
        return 2;
    }
    int final_hit = -1;
    for (int iteration = 0; iteration < iterations; iteration++) {
        coverage_reset();
        int rc = LLVMFuzzerTestOneInput(data, size);
        (void)rc;
        hashes[iteration] = g_coverage_hash;
        guard_hits[iteration] = g_guards_hit;
        entry_hits[iteration] = entry_hit(entry_symbol);
        if (iteration == 0)
            final_hit = entry_hits[iteration];
    }
    int report_rc = write_report(report_path, entry_symbol, final_hit, size,
                                 hashes, guard_hits, entry_hits, iterations);
    free(hashes); free(guard_hits); free(entry_hits); free(data);
    return report_rc == 0 ? 0 : 2;
}

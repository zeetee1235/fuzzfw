/* SPDX-License-Identifier: Apache-2.0 */
#include "fuzzfw_events.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static fuzzfw_input_stream g_input = {NULL, 0, 0};
static uint64_t g_run_frames = 0;
static uint64_t g_run_state_hash = 1469598103934665603ULL;
static int g_prev_state = 0;
#define FUZZFW_MAX_TRANSITIONS 1024u
static int g_transition_from[FUZZFW_MAX_TRANSITIONS];
static int g_transition_to[FUZZFW_MAX_TRANSITIONS];
static unsigned g_transition_count = 0;

static uint64_t mix_u64(uint64_t value) {
    value ^= value >> 33;
    value *= 0xff51afd7ed558ccdULL;
    value ^= value >> 33;
    return value;
}

void fuzzfw_input_bind(const uint8_t *data, size_t size) {
    g_input.data = data;
    g_input.size = size;
    g_input.cursor = 0;
}

void fuzzfw_input_clear(void) {
    fuzzfw_input_bind(NULL, 0);
}

fuzzfw_input_stream *fuzzfw_input_get(void) {
    return &g_input;
}

size_t fuzzfw_input_read(void *dst, size_t requested) {
    if (dst == NULL || requested == 0 || g_input.data == NULL || g_input.cursor >= g_input.size) {
        return 0;
    }
    size_t available = g_input.size - g_input.cursor;
    size_t copied = requested < available ? requested : available;
    memcpy(dst, g_input.data + g_input.cursor, copied);
    g_input.cursor += copied;
    return copied;
}

size_t fuzzfw_input_remaining(void) {
    if (g_input.data == NULL || g_input.cursor >= g_input.size) {
        return 0;
    }
    return g_input.size - g_input.cursor;
}

const uint8_t *fuzzfw_input_peek(size_t *available) {
    if (g_input.data == NULL || g_input.cursor >= g_input.size) {
        if (available != NULL) {
            *available = 0;
        }
        return NULL;
    }
    if (available != NULL) {
        *available = g_input.size - g_input.cursor;
    }
    return g_input.data + g_input.cursor;
}

void fuzzfw_run_begin(void) {
    g_run_frames = 0;
    g_run_state_hash = 1469598103934665603ULL;
    g_prev_state = 0;
    g_transition_count = 0;
}

static void record_transition(int from, int to) {
    for (unsigned i = 0; i < g_transition_count; i++) {
        if (g_transition_from[i] == from && g_transition_to[i] == to) {
            return;
        }
    }
    if (g_transition_count < FUZZFW_MAX_TRANSITIONS) {
        g_transition_from[g_transition_count] = from;
        g_transition_to[g_transition_count] = to;
        g_transition_count++;
    }
}

void fuzzfw_run_frame(uint32_t index, int state) {
    record_transition(g_prev_state, state);
    g_prev_state = state;
    g_run_frames++;
    g_run_state_hash ^= mix_u64((uint64_t)index + 0x9e3779b97f4a7c15ULL);
    g_run_state_hash ^= mix_u64((uint64_t)(uint32_t)state);
    g_run_state_hash *= 1099511628211ULL;
}

uint64_t fuzzfw_run_frames(void) {
    return g_run_frames;
}

uint64_t fuzzfw_run_state_hash(void) {
    return g_run_state_hash;
}

void fuzzfw_invariant_failed(const char *name) {
    fprintf(stderr, "fuzzfw invariant violated: %s\n", name == NULL ? "unknown" : name);
    fflush(stderr);
    abort();
}

unsigned fuzzfw_run_transition_count(void) {
    return g_transition_count;
}

int fuzzfw_run_transition_from(unsigned index) {
    return index < g_transition_count ? g_transition_from[index] : 0;
}

int fuzzfw_run_transition_to(unsigned index) {
    return index < g_transition_count ? g_transition_to[index] : 0;
}

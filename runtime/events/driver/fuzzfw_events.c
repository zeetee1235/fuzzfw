/* SPDX-License-Identifier: Apache-2.0 */
#include "fuzzfw_events.h"

#include <string.h>

static fuzzfw_input_stream g_input = {NULL, 0, 0};

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

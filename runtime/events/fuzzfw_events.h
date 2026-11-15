/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FUZZFW_EVENTS_H
#define FUZZFW_EVENTS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Adapter-visible input cursor. The harness binds it before the entry call. */
typedef struct fuzzfw_input_stream {
    const uint8_t *data;
    size_t size;
    size_t cursor;
} fuzzfw_input_stream;

void fuzzfw_input_bind(const uint8_t *data, size_t size);
void fuzzfw_input_clear(void);
fuzzfw_input_stream *fuzzfw_input_get(void);
size_t fuzzfw_input_read(void *dst, size_t requested);
size_t fuzzfw_input_remaining(void);
const uint8_t *fuzzfw_input_peek(size_t *available);

/* Optional state-machine observation used by sequence/state probes. */
void fuzzfw_run_begin(void);
void fuzzfw_run_frame(uint32_t index, int state);
uint64_t fuzzfw_run_frames(void);
uint64_t fuzzfw_run_state_hash(void);

#ifdef __cplusplus
}
#endif

#endif

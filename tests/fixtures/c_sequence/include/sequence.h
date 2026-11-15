/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FUZZFW_SEQUENCE_H
#define FUZZFW_SEQUENCE_H

#include <stddef.h>
#include <stdint.h>

typedef struct SequenceState {
    int state;
    unsigned resets;
} SequenceState;

int sequence_state_init(SequenceState *state);
void sequence_state_reset(SequenceState *state);
void sequence_state_frame_reset(SequenceState *state);
int sequence_state_probe(SequenceState *state);
int frame_value(SequenceState *state, const uint8_t *data, size_t len);

#endif

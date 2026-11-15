/* SPDX-License-Identifier: Apache-2.0 */
#include "sequence.h"

int sequence_state_init(SequenceState *state) {
    if (state == NULL) {
        return -1;
    }
    state->state = 0;
    state->resets = 0;
    return 0;
}

void sequence_state_reset(SequenceState *state) {
    if (state != NULL) {
        state->state = 0;
        state->resets = 0;
    }
}

void sequence_state_frame_reset(SequenceState *state) {
    if (state != NULL) {
        state->resets++;
    }
}

int sequence_state_probe(SequenceState *state) {
    if (state == NULL) {
        return -1;
    }
    return state->state * 32 + (int)(state->resets % 32);
}

int frame_value(SequenceState *state, const uint8_t *data, size_t len) {
    if (state == NULL || data == NULL || len < 1) {
        return -1;
    }
    /* Each frame must carry the command expected by the current state. */
    if (data[0] != (uint8_t)(0x10 + state->state)) {
        return -1;
    }
    state->state++;
    return (int)data[0];
}

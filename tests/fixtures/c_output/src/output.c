/* SPDX-License-Identifier: Apache-2.0 */
#include "output.h"

int decode_output(const uint8_t *in, size_t len, uint8_t *out, size_t cap) {
    if (in == NULL || out == NULL || len < 1 || cap < 1) {
        return -1;
    }
    out[0] = in[0];
    if (in[0] == 0x42U) {
        /* Intentional fixture bug: write beyond the configured output capacity. */
        out[80] = 1;
    }
    return 0;
}

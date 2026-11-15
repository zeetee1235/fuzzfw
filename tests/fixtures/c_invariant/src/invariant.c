/* SPDX-License-Identifier: Apache-2.0 */
#include "invariant.h"

int decode_packet(const uint8_t *data, size_t len, uint8_t *out, size_t cap) {
    if (data == NULL || out == NULL || len < 2 || cap < 1) {
        return -1;
    }
    switch (data[0]) {
    case 0x10:
        out[0] = data[1];
        return 1;
    case 0x42:
        /* Intentional fixture bug: claims success but writes the wrong magic. */
        out[0] = 0x00;
        return 2;
    default:
        return -1;
    }
}

int packet_invariant(int ret, const uint8_t *out, size_t cap) {
    if (ret == 2) {
        if (out == NULL || cap < 1 || out[0] != 0x42) {
            return 1;
        }
    }
    return 0;
}

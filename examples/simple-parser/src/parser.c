/* SPDX-License-Identifier: Apache-2.0 */
#include "parser.h"

#include <stdlib.h>
#include <string.h>

int parse_header(const uint8_t *data, size_t len) {
    if (data == NULL || len < 2) {
        return -1;
    }
    return (int)data[0] + (int)data[1];
}

int parse_packet(const uint8_t *data, size_t len) {
    if (data == NULL || len < 3) {
        return -1;
    }
    uint8_t type = data[0];
    uint8_t payload_len = data[1];
    if ((size_t)payload_len + 2U > len) {
        return -1;
    }
    if (type == 0x42U) {
        uint8_t *out = (uint8_t *)malloc(4U);
        if (out == NULL) {
            return -1;
        }
        /* Intentional fixture bug: payload_len may exceed the 4-byte buffer. */
        memcpy(out, data + 2, payload_len);
        int result = (int)out[0] + (int)out[1];
        free(out);
        return result;
    }
    return (int)data[2];
}

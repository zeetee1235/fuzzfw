/* SPDX-License-Identifier: Apache-2.0 */
#include "interproc.h"

static int read_first(const uint8_t *data) {
    return (int)data[0];
}

int handler(const uint8_t *data, size_t len) {
    if (data == NULL || len < 1) {
        return -1;
    }
    return read_first(data);
}

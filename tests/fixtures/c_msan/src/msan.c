/* SPDX-License-Identifier: Apache-2.0 */
#include "msan.h"

#include <stdlib.h>

__attribute__((noinline)) static int read_byte(const uint8_t *buffer) {
    return buffer[0];
}

int read_uninitialized(const uint8_t *data, size_t len) {
    if (data == NULL || len < 1) {
        return -1;
    }
    if (data[0] != 0x42U) {
        return 0;
    }
    uint8_t *buffer = (uint8_t *)malloc(4);
    if (buffer == NULL) {
        return -1;
    }
    /* Intentional fixture bug: reads uninitialized heap memory. */
    int value = read_byte(buffer);
    free(buffer);
    return value;
}

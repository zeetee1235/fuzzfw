/* SPDX-License-Identifier: Apache-2.0 */
#include "sequence.h"

int frame_value(const uint8_t *data, size_t len) {
    if (data == NULL || len < 1) {
        return -1;
    }
    int value = 0;
    for (size_t i = 0; i < len; ++i) {
        value ^= (int)data[i];
    }
    return value;
}

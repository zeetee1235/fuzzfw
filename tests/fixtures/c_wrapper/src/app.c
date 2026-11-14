/* SPDX-License-Identifier: Apache-2.0 */
#include "app.h"

static int initialized = 0;

void app_test_init(void) {
    initialized = 1;
}

int app_process(const uint8_t *data, size_t len) {
    if (!initialized || data == NULL || len < 2) {
        return -1;
    }
    uint8_t value = 0;
    for (size_t i = 0; i < len; ++i) {
        value ^= data[i];
    }
    return (int)value;
}

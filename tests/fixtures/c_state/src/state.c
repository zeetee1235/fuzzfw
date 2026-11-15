/* SPDX-License-Identifier: Apache-2.0 */
#include "state.h"

void state_setup(void) {
}

int stateful(const uint8_t *data, size_t len) {
    static unsigned calls;
    calls++;
    if (data == NULL || len < 1) {
        return -1;
    }
    if ((calls & 1U) == 0U) {
        return (int)data[0];
    }
    return (int)data[len - 1U];
}

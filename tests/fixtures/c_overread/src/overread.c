/* SPDX-License-Identifier: Apache-2.0 */
#include "overread.h"

int read_past(const uint8_t *data, size_t len) {
    if (data == NULL || len < 2) {
        return -1;
    }
    /* Intentional fixture bug: reads past a two-byte exact-size input. */
    return (int)data[0] + (int)data[4];
}

/* SPDX-License-Identifier: Apache-2.0 */
#include "command_seeds.h"

int command_seed_entry(const uint8_t *data, size_t len) {
    if (data == NULL || len < 1) {
        return -1;
    }
    switch (data[0]) {
    case 0x10:
        return 0;
    case 0x42:
        /* Intentional fixture bug: only reached by the synthesized command seed. */
        return data[2];
    default:
        return -1;
    }
}

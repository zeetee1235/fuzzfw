/* SPDX-License-Identifier: Apache-2.0 */
#include "commands.h"

int handle_command(const uint8_t *data, size_t len) {
    if (data == NULL || len < 2) {
        return -1;
    }
    switch (data[0]) {
    case 0x10:
        return data[1];
    case 0x42:
        /* Intentional fixture bug: command 0x42 with a short frame over-reads. */
        return data[2];
    default:
        return -1;
    }
}

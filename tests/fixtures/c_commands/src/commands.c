/* SPDX-License-Identifier: Apache-2.0 */
#include "commands.h"

enum Command {
    CMD_PING = 0x10,
    CMD_BUG = 0x42
};

int handle_command(const uint8_t *data, size_t len) {
    if (data == NULL || len < 2) {
        return -1;
    }
    switch (data[0]) {
    case CMD_PING:
        return data[1];
    case CMD_BUG:
        /* Intentional fixture bug: command 0x42 with a short frame over-reads. */
        return data[2];
    default:
        return -1;
    }
}

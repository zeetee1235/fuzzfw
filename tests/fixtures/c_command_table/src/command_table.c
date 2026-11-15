/* SPDX-License-Identifier: Apache-2.0 */
#include "command_table.h"

struct command {
    uint8_t id;
    const char *name;
};

static const struct command commands[] = {
    {0x10, "ping"},
    {0x42, "bug"},
};

static int run_command(uint8_t id, const uint8_t *data, size_t len) {
    if (id == 0x10) {
        return (int)data[1];
    }
    if (id == 0x42) {
        /* Intentional fixture bug: command 0x42 with a short frame over-reads. */
        return (int)data[2];
    }
    return -1;
}

int command_table_entry(const uint8_t *data, size_t len) {
    if (data == NULL || len < 1) {
        return -1;
    }
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
        if (commands[i].id == data[0]) {
            return run_command(commands[i].id, data, len);
        }
    }
    return -1;
}

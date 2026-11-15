/* SPDX-License-Identifier: Apache-2.0 */
#include "alias.h"

struct Cursor {
    const uint8_t *ptr;
};

static int read_cursor(const uint8_t *cursor) {
    return (int)cursor[0];
}

int alias_handler(const uint8_t *data, size_t len) {
    struct Cursor cursor;
    const uint8_t *other;
    if (data == NULL || len < 1) {
        return -1;
    }
    cursor.ptr = data;
    other = cursor.ptr;
    return read_cursor(other);
}

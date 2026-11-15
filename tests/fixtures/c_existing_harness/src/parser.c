/* SPDX-License-Identifier: Apache-2.0 */
#include "parser.h"

int existing_parse(const uint8_t *data, size_t len) {
    if (data == NULL || len < 1) {
        return -1;
    }
    return (int)data[0] ^ (int)data[len - 1];
}

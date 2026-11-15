/* SPDX-License-Identifier: Apache-2.0 */
#include "multi.h"

int parse_alpha(const uint8_t *data, size_t len) {
    return (data == NULL || len < 1) ? -1 : (int)data[0];
}

int parse_beta(const uint8_t *data, size_t len) {
    return (data == NULL || len < 2) ? -1 : (int)data[1];
}

int parse_gamma(const uint8_t *data, size_t len) {
    return (data == NULL || len < 3) ? -1 : (int)data[2];
}

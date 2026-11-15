/* SPDX-License-Identifier: Apache-2.0 */
#include "parser.h"

static int ready;

void test_setup(void) {
    ready = 1;
}

void test_teardown(void) {
    ready = 0;
}

int parser_process(const uint8_t *data, size_t len) {
    if (ready != 1) {
        return -1;
    }
    if (data == NULL || len < 1) {
        return 0;
    }
    return (int)data[0];
}

int parser_invariant(int ret) {
    return ret < 0;
}

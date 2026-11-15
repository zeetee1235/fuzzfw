/* SPDX-License-Identifier: Apache-2.0 */
#include "parser.h"

void test_parser(void) {
    test_setup();
    parser_process((const uint8_t *)"\x01", 1);
    test_teardown();
}

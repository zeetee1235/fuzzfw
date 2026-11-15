/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FUZZFW_UNIT_TEST_PARSER_H
#define FUZZFW_UNIT_TEST_PARSER_H

#include <stddef.h>
#include <stdint.h>

void test_setup(void);
void test_teardown(void);
int parser_process(const uint8_t *data, size_t len);
int parser_invariant(int ret);

#endif

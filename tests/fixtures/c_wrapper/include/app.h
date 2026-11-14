/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FUZZFW_WRAPPER_APP_H
#define FUZZFW_WRAPPER_APP_H

#include <stddef.h>
#include <stdint.h>

void app_test_init(void);
int app_process(const uint8_t *data, size_t len);

#endif

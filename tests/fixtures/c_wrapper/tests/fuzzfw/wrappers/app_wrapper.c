/* SPDX-License-Identifier: Apache-2.0 */
#include <stddef.h>
#include <stdint.h>
#include "app.h"

void fuzzfw_target(const uint8_t *data, size_t size) {
    app_test_init();
    (void)app_process(data, size);
}

/* SPDX-License-Identifier: Apache-2.0 */
#include <stddef.h>
#include <stdint.h>

#include "parser.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 64) {
        return 0;
    }
    (void)existing_parse(data, size);
    return 0;
}

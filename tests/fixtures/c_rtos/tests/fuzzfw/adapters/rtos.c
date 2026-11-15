/* SPDX-License-Identifier: Apache-2.0 */
#include "events.h"
#include "fuzzfw_events.h"

int xTaskNotifyWait(uint8_t *dst, size_t requested) {
    if (dst == NULL || requested == 0) {
        return -1;
    }
    return fuzzfw_input_read(dst, requested) == requested ? 0 : -1;
}

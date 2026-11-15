/* SPDX-License-Identifier: Apache-2.0 */
#include "events.h"

int isr_process(const uint8_t *packet, size_t len) {
    if (packet == NULL || len < 1) {
        return -1;
    }
    uint8_t buffer[8];
    size_t requested = len > sizeof(buffer) ? sizeof(buffer) : len;
    if (HAL_ISR_Read(buffer, requested) != 0) {
        return -1;
    }
    return (int)buffer[0] + (int)packet[0];
}

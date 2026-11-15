/* SPDX-License-Identifier: Apache-2.0 */
#include "events.h"

static volatile int rtos_is_ready = 0;

void rtos_ready(void) {
    rtos_is_ready = 1;
}

int rtos_process(const uint8_t *packet, size_t len) {
    if (packet == NULL || len < 1 || !rtos_is_ready) {
        return -1;
    }
    uint8_t buffer[8];
    size_t requested = len > sizeof(buffer) ? sizeof(buffer) : len;
    if (xTaskNotifyWait(buffer, requested) != 0) {
        return -1;
    }
    return (int)buffer[0] + (int)packet[0];
}

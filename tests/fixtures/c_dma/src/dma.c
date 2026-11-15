/* SPDX-License-Identifier: Apache-2.0 */
#include "dma.h"

static volatile int dma_flushed = 0;

void dma_event_flush(void) {
    dma_flushed = 1;
}

int dma_process(const uint8_t *packet, size_t len) {
    if (packet == NULL || len < 2 || !dma_flushed) {
        return -1;
    }
    uint8_t buffer[16];
    size_t requested = len > sizeof(buffer) ? sizeof(buffer) : len;
    if (DMA_Read(buffer, requested) != 0) {
        return -1;
    }
    int sum = 0;
    for (size_t i = 0; i < requested; ++i) {
        sum += buffer[i];
    }
    return sum + packet[0];
}

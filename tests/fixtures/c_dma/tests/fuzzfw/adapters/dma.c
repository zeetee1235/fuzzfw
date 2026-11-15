/* SPDX-License-Identifier: Apache-2.0 */
#include "dma.h"
#include "fuzzfw_events.h"

int DMA_Read(uint8_t *dst, size_t requested) {
    if (dst == NULL || requested == 0) {
        return -1;
    }
    size_t copied = fuzzfw_input_read(dst, requested);
    return copied == requested ? 0 : -1;
}

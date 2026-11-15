/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FUZZFW_DMA_H
#define FUZZFW_DMA_H

#include <stddef.h>
#include <stdint.h>

extern int DMA_Read(uint8_t *dst, size_t requested);
void dma_event_flush(void);
int dma_process(const uint8_t *packet, size_t len);

#endif

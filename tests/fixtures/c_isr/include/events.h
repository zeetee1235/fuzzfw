/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FUZZFW_ISR_H
#define FUZZFW_ISR_H

#include <stddef.h>
#include <stdint.h>

extern int HAL_ISR_Read(uint8_t *dst, size_t requested);
int isr_process(const uint8_t *packet, size_t len);

#endif

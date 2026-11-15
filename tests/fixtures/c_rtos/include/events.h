/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FUZZFW_RTOS_H
#define FUZZFW_RTOS_H

#include <stddef.h>
#include <stdint.h>

extern int xTaskNotifyWait(uint8_t *dst, size_t requested);
void rtos_ready(void);
int rtos_process(const uint8_t *packet, size_t len);

#endif

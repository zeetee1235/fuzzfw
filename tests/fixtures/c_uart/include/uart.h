/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FUZZFW_UART_FIXTURE_H
#define FUZZFW_UART_FIXTURE_H

#include <stddef.h>
#include <stdint.h>

int UART_Read(uint8_t *dst, size_t requested);
int uart_process(void);

#endif

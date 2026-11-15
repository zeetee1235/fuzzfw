/* SPDX-License-Identifier: Apache-2.0 */
#include "uart.h"

int uart_process(void) {
    uint8_t buffer[8];
    size_t got = 0;
    if (UART_Read(buffer, sizeof buffer) == 0) {
        got = sizeof buffer;
    }
    if (got < 2) {
        return -1;
    }
    return (int)buffer[0] + (int)buffer[got - 1];
}

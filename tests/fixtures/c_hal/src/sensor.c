/* SPDX-License-Identifier: Apache-2.0 */
#include "sensor.h"

int sensor_process(const uint8_t *packet, size_t len) {
    if (packet == NULL || len < 2) {
        return -1;
    }
    if (HAL_GetStatus() != 0) {
        return -1;
    }
    uint8_t count = packet[0];
    if ((size_t)count + 1U > len) {
        return -1;
    }
    uint8_t checksum = 0;
    for (size_t i = 0; i < count; i++) {
        checksum ^= packet[1U + i];
    }
    return (int)checksum;
}

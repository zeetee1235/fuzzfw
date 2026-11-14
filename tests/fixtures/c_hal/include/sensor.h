/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FUZZFW_HAL_SENSOR_H
#define FUZZFW_HAL_SENSOR_H

#include <stddef.h>
#include <stdint.h>

extern int HAL_GetStatus(void);
int sensor_process(const uint8_t *packet, size_t len);

#endif

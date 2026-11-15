/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FUZZFW_OVERREAD_H
#define FUZZFW_OVERREAD_H

#include <stddef.h>
#include <stdint.h>

int read_past(const uint8_t *data, size_t len);

#endif

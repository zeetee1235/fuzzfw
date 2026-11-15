/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FUZZFW_INTERPROC_H
#define FUZZFW_INTERPROC_H

#include <stddef.h>
#include <stdint.h>

int handler(const uint8_t *data, size_t len);

#endif

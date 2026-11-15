/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FUZZFW_MSAN_H
#define FUZZFW_MSAN_H

#include <stddef.h>
#include <stdint.h>

int read_uninitialized(const uint8_t *data, size_t len);

#endif

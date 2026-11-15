/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FUZZFW_OUTPUT_H
#define FUZZFW_OUTPUT_H

#include <stddef.h>
#include <stdint.h>

int decode_output(const uint8_t *in, size_t len, uint8_t *out, size_t cap);

#endif

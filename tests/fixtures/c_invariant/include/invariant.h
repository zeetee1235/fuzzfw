/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FUZZFW_INVARIANT_H
#define FUZZFW_INVARIANT_H

#include <stddef.h>
#include <stdint.h>

int decode_packet(const uint8_t *data, size_t len, uint8_t *out, size_t cap);
int packet_invariant(int ret, const uint8_t *out, size_t cap);

#endif

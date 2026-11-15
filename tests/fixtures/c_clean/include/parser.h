/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FUZZFW_FIXTURE_PARSER_H
#define FUZZFW_FIXTURE_PARSER_H

#include <stddef.h>
#include <stdint.h>

/* A deliberately small packet parser used by fuzzfw integration tests. */
int parse_packet(const uint8_t *data, size_t len);
int parse_header(const uint8_t *data, size_t len);
int checksum_loop(const uint8_t *data, size_t len);
int compare_buffers(const uint8_t *restrict a, size_t an,
                    const uint8_t *restrict b, size_t bn);

#endif

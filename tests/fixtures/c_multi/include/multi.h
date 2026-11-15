/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FUZZFW_MULTI_FIXTURE_H
#define FUZZFW_MULTI_FIXTURE_H

#include <stddef.h>
#include <stdint.h>

int parse_alpha(const uint8_t *data, size_t len);
int parse_beta(const uint8_t *data, size_t len);
int parse_gamma(const uint8_t *data, size_t len);

#endif

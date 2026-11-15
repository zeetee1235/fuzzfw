/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FUZZFW_COMMAND_SEEDS_H
#define FUZZFW_COMMAND_SEEDS_H

#include <stddef.h>
#include <stdint.h>

int command_seed_entry(const uint8_t *data, size_t len);

#endif

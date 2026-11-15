/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FUZZFW_COMMAND_TABLE_H
#define FUZZFW_COMMAND_TABLE_H

#include <stddef.h>
#include <stdint.h>

int command_table_entry(const uint8_t *data, size_t len);

#endif

/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FUZZFW_COMMANDS_H
#define FUZZFW_COMMANDS_H

#include <stddef.h>
#include <stdint.h>

int handle_command(const uint8_t *data, size_t len);

#endif

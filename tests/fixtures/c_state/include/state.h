/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FUZZFW_STATE_H
#define FUZZFW_STATE_H

#include <stddef.h>
#include <stdint.h>

void state_setup(void);
int stateful(const uint8_t *data, size_t len);

#endif

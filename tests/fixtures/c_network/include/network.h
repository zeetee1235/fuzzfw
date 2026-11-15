/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FUZZFW_NETWORK_FIXTURE_H
#define FUZZFW_NETWORK_FIXTURE_H

#include <stddef.h>
#include <stdint.h>

int NET_Recv(uint8_t *dst, size_t requested);
int network_process(void);

#endif

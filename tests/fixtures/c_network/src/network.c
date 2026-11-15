/* SPDX-License-Identifier: Apache-2.0 */
#include "network.h"

int network_process(void) {
    uint8_t packet[12];
    if (NET_Recv(packet, sizeof packet) != 0) {
        return -1;
    }
    if (packet[0] != 0x42U) {
        return 0;
    }
    return (int)packet[1] + (int)packet[11];
}

/* SPDX-License-Identifier: Apache-2.0 */
#include "tlv.h"

int tlv_frame(const uint8_t *data, size_t len) {
    if (data == NULL || len < 2) {
        return -1;
    }
    return (int)data[0] + (int)data[1];
}

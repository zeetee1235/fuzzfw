// SPDX-License-Identifier: Apache-2.0
#include "codec.hpp"

namespace codec {
int decode(const unsigned char *data, std::size_t len) {
    if (data == nullptr || len < 2) {
        return -1;
    }
    unsigned int value = 0;
    for (std::size_t i = 0; i < len; ++i) {
        value = (value * 33U) ^ data[i];
    }
    return static_cast<int>(value);
}
}

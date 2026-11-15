/* SPDX-License-Identifier: Apache-2.0 */
#include "msan.hpp"

extern "C" int cpp_msan_entry(const std::uint8_t *data, std::size_t len) {
    if (data == nullptr || len < 1) {
        return -1;
    }
    if (data[0] != 0x42U) {
        return 0;
    }
    auto *buffer = new std::uint8_t[4];
    /* Intentional fixture bug: reads uninitialized heap memory. */
    int value = buffer[0];
    delete[] buffer;
    return value;
}

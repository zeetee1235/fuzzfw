/* SPDX-License-Identifier: Apache-2.0 */
#include "parser.hpp"

Parser::Parser(int mode) : mode_(mode), state_(static_cast<std::uint32_t>(mode)) {}

int Parser::feed(const unsigned char *data, std::size_t len) {
    if (data == nullptr || len < 2) {
        return -1;
    }
    for (std::size_t i = 0; i < len; ++i) {
        state_ = (state_ * 33U) ^ static_cast<std::uint32_t>(data[i]);
    }
    return static_cast<int>(state_ + static_cast<std::uint32_t>(mode_));
}

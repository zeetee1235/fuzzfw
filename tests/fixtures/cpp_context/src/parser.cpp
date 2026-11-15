// SPDX-License-Identifier: Apache-2.0
#include "parser.hpp"

Parser::Parser() : state_(0) {}

Parser Parser::create_default() {
    return Parser();
}

std::unique_ptr<Parser> Parser::create_unique() {
    return std::make_unique<Parser>();
}

int Parser::hash_static(const unsigned char *data, std::size_t len) {
    if (data == nullptr || len < 2) {
        return -1;
    }
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < len; ++i) {
        value = (value * 31U) ^ static_cast<std::uint32_t>(data[i]);
    }
    return static_cast<int>(value);
}

int Parser::feed(const unsigned char *data, std::size_t len) {
    if (data == nullptr || len < 2) {
        return -1;
    }
    for (std::size_t i = 0; i < len; ++i) {
        state_ = (state_ * 33U) ^ static_cast<std::uint32_t>(data[i]);
    }
    return static_cast<int>(state_);
}

RawParser *RawParser::create() {
    return new RawParser();
}

void RawParser::destroy(RawParser *parser) {
    delete parser;
}

int RawParser::feed(const unsigned char *data, std::size_t len) {
    if (data == nullptr || len < 2) {
        return -1;
    }
    for (std::size_t i = 0; i < len; ++i) {
        state_ = (state_ * 17U) ^ static_cast<std::uint32_t>(data[i]);
    }
    return static_cast<int>(state_);
}

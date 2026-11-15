/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FUZZFW_CPP_CONSTRUCTOR_PARSER_HPP
#define FUZZFW_CPP_CONSTRUCTOR_PARSER_HPP

#include <cstddef>
#include <cstdint>

class Parser {
public:
    explicit Parser(int mode);
    int feed(const unsigned char *data, std::size_t len);

private:
    int mode_;
    std::uint32_t state_;
};

#endif

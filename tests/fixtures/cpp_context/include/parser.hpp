// SPDX-License-Identifier: Apache-2.0
#ifndef FUZZFW_CPP_CONTEXT_PARSER_HPP
#define FUZZFW_CPP_CONTEXT_PARSER_HPP

#include <cstddef>
#include <cstdint>
#include <memory>

class Parser {
public:
    Parser();
    static Parser create_default();
    static std::unique_ptr<Parser> create_unique();
    static int hash_static(const unsigned char *data, std::size_t len);
    int feed(const unsigned char *data, std::size_t len);

private:
    std::uint32_t state_ = 0;
};

class RawParser {
public:
    static RawParser *create();
    static void destroy(RawParser *parser);
    int feed(const unsigned char *data, std::size_t len);

private:
    std::uint32_t state_ = 0;
};

#endif

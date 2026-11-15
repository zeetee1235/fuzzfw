/* SPDX-License-Identifier: Apache-2.0 */
#include <stddef.h>
#include <stdint.h>

#define JSMN_HEADER
#include "jsmn.h"

#define FUZZFW_JSMN_TOKENS 64

int fuzzfw_jsmn_parse(const uint8_t *data, size_t size) {
    jsmn_parser parser;
    jsmntok_t tokens[FUZZFW_JSMN_TOKENS];
    jsmn_init(&parser);
    return jsmn_parse(&parser, (const char *)data, size, tokens, FUZZFW_JSMN_TOKENS);
}

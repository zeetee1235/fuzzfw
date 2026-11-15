/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FUZZFW_CONTEXT_H
#define FUZZFW_CONTEXT_H

#include <stddef.h>
#include <stdint.h>

typedef struct ParserContext {
    int ready;
    unsigned calls;
} ParserContext;

int parser_context_init(ParserContext *ctx);
void parser_context_reset(ParserContext *ctx);
int parser_context_process(ParserContext *ctx, const uint8_t *data, size_t len);

#endif

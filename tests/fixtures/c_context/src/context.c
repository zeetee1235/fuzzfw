/* SPDX-License-Identifier: Apache-2.0 */
#include "context.h"

int parser_context_init(ParserContext *ctx) {
    if (ctx == NULL) {
        return -1;
    }
    ctx->ready = 1;
    ctx->calls = 0;
    return 0;
}

void parser_context_reset(ParserContext *ctx) {
    if (ctx != NULL) {
        ctx->ready = 0;
        ctx->calls = 0;
    }
}

int parser_context_process(ParserContext *ctx, const uint8_t *data, size_t len) {
    if (ctx == NULL || !ctx->ready || data == NULL || len < 2) {
        return -1;
    }
    ctx->calls++;
    return (int)data[0] + (int)data[len - 1] + (int)ctx->calls;
}

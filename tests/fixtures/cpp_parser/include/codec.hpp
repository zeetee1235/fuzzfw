// SPDX-License-Identifier: Apache-2.0
#ifndef FUZZFW_CPP_CODEC_HPP
#define FUZZFW_CPP_CODEC_HPP

#include <cstddef>

namespace codec {
int decode(const unsigned char *data, std::size_t len);
}

#endif

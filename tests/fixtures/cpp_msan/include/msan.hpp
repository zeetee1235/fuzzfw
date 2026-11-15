/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FUZZFW_CPP_MSAN_HPP
#define FUZZFW_CPP_MSAN_HPP

#include <cstddef>
#include <cstdint>

extern "C" int cpp_msan_entry(const std::uint8_t *data, std::size_t len);

#endif


#include "disarm64.hpp"
#include <cstdint>

// Disarm — Fast AArch64 Decode/Encoder
// SPDX-License-Identifier: BSD-3-Clause

#define DA64_CLASSIFIER
#include "disarm64-private.inc"
#undef DA64_CLASSIFIER

namespace disarm64 {

enum Da64InstKind da64_classify(uint32_t inst) {
  return Da64InstKind(da64_classify_impl(inst));
}

}

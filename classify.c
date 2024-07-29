
#include "disarm64.h"
#include <stdint.h>

// Disarm — Fast AArch64 Decode/Encoder
// SPDX-License-Identifier: BSD-3-Clause

#define DA64_CLASSIFIER
#include "disarm64-private.inc"
#undef DA64_CLASSIFIER

enum Da64InstKind da64_classify(uint32_t inst) {
  return da64_classify_impl(inst);
}

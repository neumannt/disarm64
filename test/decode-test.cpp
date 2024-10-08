
#include "disarm64.hpp"
#include <string.h>
#include <stdint.h>
#include <stdio.h>

using namespace disarm64;

int main(void) {
  const struct {
    uint32_t inst;
    unsigned mnem;
    const char* disable_str;
    const char* mnem_str;
    const char* fmt;
  } cases[] = {
#define TESTF(cond, inst, mnem, fmt) {inst, mnem, cond ? 0 : #cond, #mnem, fmt},
#define TEST(...) TESTF(1, __VA_ARGS__)

      // clang-format off
    TEST(0x00000000, DA64I_UDF, "udf #0x0")
    TEST(0x1a000000, DA64I_ADC, "adc w0, w0, w0")
    TEST(0x1a1f03ff, DA64I_ADC, "adc wzr, wzr, wzr")
    TEST(0x9a000000, DA64I_ADC, "adc x0, x0, x0")
    TEST(0x9a1f03ff, DA64I_ADC, "adc xzr, xzr, xzr")
    TEST(0x3a000000, DA64I_ADCS, "adcs w0, w0, w0")
    TEST(0x3a1f03ff, DA64I_ADCS, "adcs wzr, wzr, wzr")
    TEST(0xba000000, DA64I_ADCS, "adcs x0, x0, x0")
    TEST(0xba1f03ff, DA64I_ADCS, "adcs xzr, xzr, xzr")
    TEST(0x5a000000, DA64I_SBC, "sbc w0, w0, w0")
    TEST(0x5a1f03ff, DA64I_SBC, "sbc wzr, wzr, wzr")
    TEST(0xda000000, DA64I_SBC, "sbc x0, x0, x0")
    TEST(0xda1f03ff, DA64I_SBC, "sbc xzr, xzr, xzr")
    TEST(0x7a000000, DA64I_SBCS, "sbcs w0, w0, w0")
    TEST(0x7a1f03ff, DA64I_SBCS, "sbcs wzr, wzr, wzr")
    TEST(0xfa000000, DA64I_SBCS, "sbcs x0, x0, x0")
    TEST(0xfa1f03ff, DA64I_SBCS, "sbcs xzr, xzr, xzr")
    TEST(0x0b204000, DA64I_ADD_EXT, "add w0, w0, w0, uxtw #0")
    TEST(0x0b204c00, DA64I_ADD_EXT, "add w0, w0, w0, uxtw #3")
    TEST(0x0b205000, DA64I_ADD_EXT, "add w0, w0, w0, uxtw #4")
    TEST(0x0b205400, DA64I_UNKNOWN, "")
    TEST(0x0b206000, DA64I_ADD_EXT, "add w0, w0, w0, uxtx #0")
    TEST(0x8b206000, DA64I_ADD_EXT, "add x0, x0, x0, uxtx #0")
    TEST(0x8b2063ff, DA64I_ADD_EXT, "add sp, sp, x0, uxtx #0")
    TEST(0x8b20e000, DA64I_ADD_EXT, "add x0, x0, x0, sxtx #0")
    TEST(0x8b3fe000, DA64I_ADD_EXT, "add x0, x0, xzr, sxtx #0")
    TEST(0x8b204000, DA64I_ADD_EXT, "add x0, x0, w0, uxtw #0")
    TEST(0xd4400000, DA64I_HLT, "hlt #0x0")
    TEST(0x1e23c020, DA64I_FCVT, "fcvt h0, s1")
    TESTF(DA64_HAVE_BF16, 0x1e634020, DA64I_BFCVT, "bfcvt h0, s1")
  // clang-format on

#include "decode-test-branchreg.inc"
#include "decode-test-fmovimm.inc"
#include "decode-test-immlogical.inc"
#include "decode-test-immsimd.inc"
#include "decode-test-pauth.inc"
  };

  char buf[128];
  struct Da64Inst res;

  printf("1..%zu\n", sizeof(cases) / sizeof(cases[0]));
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    da64_decode(cases[i].inst, &res);
    da64_format(&res, buf);

    if (cases[i].disable_str) {
      if (res.mnem == DA64I_UNKNOWN && buf[0] == '\0')
        printf("ok %zu %08x %s (%s) # skip %s\n", i + 1, cases[i].inst,
               cases[i].fmt, cases[i].mnem_str, cases[i].disable_str);
      else
        printf("not ok %zu %08x %s (%s) (!%s)\n", i + 1, cases[i].inst,
               cases[i].fmt, cases[i].mnem_str, cases[i].disable_str);
    } else {
      int ok = res.mnem == cases[i].mnem && !strcmp(buf, cases[i].fmt);
      printf("%sok %zu %08x %s (%s)\n", &"not "[4 * ok], i + 1, cases[i].inst,
             cases[i].fmt, cases[i].mnem_str);
      if (!ok) {
        printf("# mnem: got=%#x expected=%#x (%s)\n", res.mnem, cases[i].mnem,
               cases[i].mnem_str);
        printf("# fmt: got=%s expected=%s\n", buf, cases[i].fmt);
      }
    }
  }

  return 0;
}

#ifndef DA_DISARM64_H_
#define DA_DISARM64_H_

// Disarm — Fast AArch64 Decode/Encoder
// SPDX-License-Identifier: BSD-3-Clause

#include <cstdbool>
#include <cstddef>
#include <cstdint>

namespace disarm64 {

enum Da64Cond {
  /// Equals, zero set (Z=1)
  DA_EQ = 0x0,
  /// Not equals, zero clear (Z=0)
  DA_NE = 0x1,
  /// Higher or same, carry set (C=1)
  DA_CS = 0x2,
  /// Higher or same, carry set (C=1)
  DA_HS = 0x2,
  /// Lower, carry clear (C=0)
  DA_CC = 0x3,
  /// Lower, carry clear (C=0)
  DA_LO = 0x3,
  /// Minus, negate set (N=1)
  DA_MI = 0x4,
  /// Plus, negate clear (N=0)
  DA_PL = 0x5,
  /// Overflow set (V=1)
  DA_VS = 0x6,
  /// Overflow clear (V=0)
  DA_VC = 0x7,
  /// Higher (C=1 & Z=0)
  DA_HI = 0x8,
  /// Lower or same (C=0 | Z=1)
  DA_LS = 0x9,
  /// Greater than or equal (N=V)
  DA_GE = 0xa,
  /// Less than (N!=V)
  DA_LT = 0xb,
  /// Greater than (Z=0 & N=V)
  DA_GT = 0xc,
  /// Less than or equal (Z=1 | N!=V)
  DA_LE = 0xd,
  /// Always
  DA_AL = 0xe,
  /// Always (encoding never)
  DA_NV = 0xf,
};

typedef enum Da64Cond Da64Cond;

enum Da64PrfOp {
  DA_PRF_PLDL1KEEP = 0,
  DA_PRF_PLDL1STRM = 1,
  DA_PRF_PLDL2KEEP = 2,
  DA_PRF_PLDL2STRM = 3,
  DA_PRF_PLDL3KEEP = 4,
  DA_PRF_PLDL3STRM = 5,
  DA_PRF_PLIL1KEEP = 8,
  DA_PRF_PLIL1STRM = 9,
  DA_PRF_PLIL2KEEP = 10,
  DA_PRF_PLIL2STRM = 11,
  DA_PRF_PLIL3KEEP = 12,
  DA_PRF_PLIL3STRM = 13,
  DA_PRF_PSTL1KEEP = 16,
  DA_PRF_PSTL1STRM = 17,
  DA_PRF_PSTL2KEEP = 18,
  DA_PRF_PSTL2STRM = 19,
  DA_PRF_PSTL3KEEP = 20,
  DA_PRF_PSTL3STRM = 21,
};

typedef enum Da64PrfOp Da64PrfOp;

// Encoding API

struct GReg {
  uint8_t val;
};
struct GRegZR {
  uint8_t val;
  constexpr explicit GRegZR(uint8_t v) : val(v) {}
  constexpr GRegZR(GReg r) : val(r.val) {}
};
struct GRegSP {
  uint8_t val;
  constexpr explicit GRegSP(uint8_t v) : val(v) {}
  constexpr GRegSP(GReg r) : val(r.val) {}
};
struct VReg {
  uint8_t val;
};

static inline constexpr GReg DA_GP(uint8_t num) {
  return GReg{uint8_t(num & 31)};
}
static constexpr GRegZR DA_ZR = GRegZR{31};
static constexpr GRegSP DA_SP = GRegSP{31};
static constexpr VReg DA_V(uint8_t num) { return VReg{uint8_t(num & 31)}; }

static inline constexpr GRegSP DA_GPSP(GRegSP r) { return r; }
static inline constexpr GRegZR DA_GPZR(GRegZR r) { return r; }
static inline constexpr uint8_t DA_REGVAL(GReg r) { return r.val; }
static inline constexpr uint8_t DA_REGVAL(GRegZR r) { return r.val; }
static inline constexpr uint8_t DA_REGVAL(GRegSP r) { return r.val; }
static inline constexpr uint8_t DA_REGVAL(VReg r) { return r.val; }

/// Convenience definitions
static constexpr auto x0 = DA_GP(0), x1 = DA_GP(1), x2 = DA_GP(2),
                      x3 = DA_GP(3), x4 = DA_GP(4), x5 = DA_GP(5),
                      x6 = DA_GP(6), x7 = DA_GP(7), x8 = DA_GP(8),
                      x9 = DA_GP(9), x10 = DA_GP(10), x11 = DA_GP(11),
                      x12 = DA_GP(12), x13 = DA_GP(13), x14 = DA_GP(14),
                      x15 = DA_GP(15), x16 = DA_GP(16), x17 = DA_GP(17),
                      x18 = DA_GP(18), x19 = DA_GP(19), x20 = DA_GP(20),
                      x21 = DA_GP(21), x22 = DA_GP(22), x23 = DA_GP(24),
                      x25 = DA_GP(25), x26 = DA_GP(26), x27 = DA_GP(27),
                      x28 = DA_GP(28), x29 = DA_GP(29), x30 = DA_GP(30);
static constexpr auto sp = DA_SP;
static constexpr auto xzr = DA_ZR;

// Do not use. Sign extend lowest bits of imm.
static inline int64_t da_sext(int64_t imm, unsigned bits) {
  uint64_t mask = (uint64_t(1) << bits) - 1;
  uint64_t sign = uint64_t(1) << (bits - 1);
  return imm & sign ? ((imm & mask) ^ sign) - sign : (imm & mask);
}
// Do not use. Encodes arithmetic immediate.
uint32_t __attribute__((const)) da_immadd(int64_t value);
// Do not use. Encodes logical immediate.
uint32_t __attribute__((const)) da_immlogical(uint64_t value, unsigned is64);
// Do not use. Encodes floating-point immediate.
uint32_t __attribute__((const)) da_immfmov32(float value);
// Do not use. Encodes floating-point immediate.
uint32_t __attribute__((const)) da_immfmov64(double value);
// Do not use. Encodes SIMD MOVI/MVNI immediate.
uint32_t __attribute__((const)) da_immsimdmovi(uint64_t value);

// Defines enum Da64InstKind, enum Da64InstGroup, the macro DA64_GROUP(mnem)
// and declares the encoding functions (or function-like macros)
#include <disarm64-public.inc>

/// Materialize cnst into reg; may write up to four instructions. Returns the
/// number of instructions written.
unsigned MOVconst(uint32_t* buf, GReg reg, uint64_t cnst);

// Decoding API

enum Da64Ext {
  DA_EXT_UXTB = 0,
  DA_EXT_UXTH = 1,
  DA_EXT_UXTW = 2,
  DA_EXT_UXTX = 3,
  DA_EXT_SXTB = 4,
  DA_EXT_SXTH = 5,
  DA_EXT_SXTW = 6,
  DA_EXT_SXTX = 7,
  DA_EXT_LSL = 8,
  DA_EXT_LSR = 9,
  DA_EXT_ASR = 10,
  DA_EXT_ROR = 11,
};

enum Da64VectorArrangement {
  DA_VA_8B = 0,
  DA_VA_16B = 1,
  DA_VA_4H = 2,
  DA_VA_8H = 3,
  DA_VA_2S = 4,
  DA_VA_4S = 5,
  DA_VA_1D = 6,
  DA_VA_2D = 7,
  // special, only for group FP_HORZ_SCALAR
  DA_VA_2H = 8,
  // special
  DA_VA_1Q = 9,
};

enum Da64OpType {
  DA_OP_NONE = 0,
  /// General-purpose register. reg := Xn/31=ZR; reggp is valid.
  DA_OP_REGGP,
  /// General-purpose register increment. reg := Xn/31=ZR; reggp is valid.
  DA_OP_REGGPINC,
  /// Modified GP reg; reg := Xn/31=ZR; reggpext is valid.
  DA_OP_REGGPEXT,
  /// Stack Pointer; reggp is valid.
  DA_OP_REGSP,
  /// Scalar FP/vector reg; reg is vector reg; regfp is valid.
  DA_OP_REGFP,
  /// Vector; reg is vector reg; regvec is valid.
  DA_OP_REGVEC,
  /// Vector table, reg is vector reg; regvtbl is valid.
  DA_OP_REGVTBL,
  /// Vector element, reg is vector reg; regvidx is valid.
  DA_OP_REGVIDX,
  /// Vector table element, reg is vector reg; regvtblidx is valid.
  DA_OP_REGVTBLIDX,
  /// Memory with offset; reg is base or SP; offset in uimm16.
  DA_OP_MEMUOFF,
  /// Memory with offset; reg is base or SP; offset in simm16.
  DA_OP_MEMSOFF,
  /// Memory with pre-indexed offset; reg is base or SP; offset in simm16.
  DA_OP_MEMSOFFPRE,
  /// Memory with post-indexed offset; reg is base or SP; offset in simm16.
  DA_OP_MEMSOFFPOST,
  /// Memory with register offset; reg is base or SP; memreg is valid.
  DA_OP_MEMREG,
  /// Memory with post-incremented register; reg is base or SP; memreg is valid.
  DA_OP_MEMREGPOST,
  /// Memory with increment; reg is base or zero
  DA_OP_MEMINC,
  /// Condition code; cond is valid.
  DA_OP_COND,
  /// Prefetch operation; prfop is the operation.
  DA_OP_PRFOP,
  /// System register; sysreg encodes op1:CRn:CRm:op2.
  DA_OP_SYSREG,
  /// Small unsigned immediate <= 64, printed as decimal; stored in uimm16.
  DA_OP_IMMSMALL,
  /// Signed 16 bits immediate; value stored in simm16.
  DA_OP_SIMM,
  /// Unsigned 16 bits immediate; value stored in uimm16.
  DA_OP_UIMM,
  /// Unsigned 16 bits immediate; immshift is valid; value stored in uimm16.
  DA_OP_UIMMSHIFT,
  /// Large immediate, stored in imm64.
  DA_OP_IMMLARGE,
  /// Floating-point immediate, stored in float8.
  DA_OP_IMMFLOAT,
};

struct Da64Op {
  uint8_t type; // enum Da64OpType
  union {
    uint8_t reg;
    uint8_t prfop; // enum Da64PrfOp
    struct {
      uint8_t mask : 1; // 0 = LSL, 1 = MSL
      uint8_t shift : 7;
    } immshift;
  };
  union {
    struct {
      uint8_t sf : 1;
    } reggp;
    struct {
      uint8_t sf : 1;
      uint8_t ext : 7; // enum Da64Ext
      uint8_t shift;
    } reggpext;
    struct {
      uint8_t size;
    } regfp;
    struct {
      uint8_t va; // enum Da64VectorArrangement
    } regvec;
    struct {
      // 0=b, 1=h, 2=s, 3=d, (4=q), 5=2b, 6=4b, 7=2h
      uint8_t esize;
      uint8_t elem;
    } regvidx;
    struct {
      uint8_t va; // enum Da64VectorArrangement
      uint8_t cnt;
    } regvtbl;
    struct {
      uint8_t esize : 4;
      uint8_t elem : 4;
      uint8_t cnt;
    } regvtblidx;
    struct {
      uint8_t sc : 1;
      uint8_t ext : 4; // enum Da64Ext
      uint8_t shift : 3;
      uint8_t offreg;
    } memreg;
    uint16_t sysreg;
    uint16_t uimm16;
    int16_t simm16;
    uint8_t cond; // Da64Cond
  };
};

struct Da64Inst {
  uint16_t mnem; // enum Da64InstKind
  struct Da64Op ops[5];
  union {
    uint64_t imm64;
    float float8;
  };
};

enum Da64InstKind da64_classify(uint32_t inst);
void da64_decode(uint32_t inst, struct Da64Inst* ddi);
void da64_format(const struct Da64Inst* ddi, char* buf128);

}

#endif

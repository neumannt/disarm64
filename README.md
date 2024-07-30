# Disarm — Fast AArch64 Decode/Encoder

A variant of [https://github.com/aengelke/disarm](disarm) that offers 
a C++ interface and an assembler helper.

## Encoder

The encoder generally exposes one function per instruction mnemonic/form/operation size/etc., e.g., `ADDw_uxtw(Rd,Rn,Rm,imm)` for 32-bit `add` with `uxtw` extension or `STRwu(Rt,Rn,imm)` for 32-bit `str` with an unsigned immediate offset. When invalid arguments (e.g., out-of-range immediate) are passed and the instruction is not encodable, functions return zero. The API is designed to be usable like this:

```c++
if (uint32_t inst = ADDxi(ra, rb, imm)) {
    asm.add(inst);
} else {
    DA_GReg tmp = allocTempReg();
    asm.MOVconst(tmp, imm);
    asm.add(da_ADDx(ra, rb, tmp));
    freeTempReg();
}
```

Register classes are exposed as data types. General-purpose registers (`DA_GP(num)`) that are not `sp`/`xzr` have type `DA_GReg`, `DA_ZR` has type `DA_GRegZR`, `DA_SP` has type `DA_GRegSP`, and floating-point/SIMD registers `DA_V(num)` have type `DA_VReg`. Whenever a GP-or-ZR/GP-or-SP is accepted, functions accept both `DA_GReg` and `DA_GRegZR`/`DA_GRegSP`.

There are a few functions, which operate differently than standard assembler instructions:

- `MOVconst(uint32_t* buf, DA_GReg, uint64_t)` produces a sequence of up to 4 instructions into the buffer to materialize the constant in the general-purpose register. The function returns the number of instructions written.
- `add/sub` with immediate (`ADDxi` etc.) shift the immediate as required and also convert between `add`/`sub` as required, so encoding `add x0, x1, -1` will succeed and be transparently encoded as `sub x0, x1, 1`. This also works (and is correct) when flags are updated.

- `MOVId/MOVI2d(DA_VReg, uint64_t)` tries to materialize the constant in a single `MOVI` instruction using an appropriate encoding.
- Assembly aliases (e.g., `lsl`, `cmp`) are provided in most cases. `mov` to/from `sp` is named `MOV_SPx` for disambiguation.

## Decoder

The decoder consists of three separate stages:

- Instruction validation and classification (`classify`). Takes one instruction (a `uint32_t`) and, if the instruction is valid, returns the instruction kind (`enum Da64InstKind`, e.g., `DA64I_ADD_IMM`).
- Operand decoding (`decode`). Takes one instruction, classifies the instruction, and decodes operands into a `struct Da64Inst`. Different encodings of immediates, register numbers, vector element indices, etc. are unified. Note that AArch64 has a large amount of different operand types (see `enum Da64OpType` in [disarm64.hpp](disarm64.hpp)).
- Formatting (`format`). Takes a `struct Da64Inst` and formats the instruction as string. Currently, preferred disassembly aliases are not used, but this might change in future.

## Supported Extensions

Roughly all ISA extensions introduced in ARMv8.8 and earlier are currently supported, with the exception of SVE (+F32MM/F64MM). Some more recent extensions are also supported. See [feat.txt](feat.txt) for a full list, all listed extensions that have no `incomplete:` line are fully supported.

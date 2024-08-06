
#include "disarm64.hpp"
#include "assembler.hpp"
#include <iostream>
#include <fstream>
#include <vector>
#include <cstdio>
#include <dlfcn.h>

using namespace disarm64;
using namespace std;

static unsigned countRun(istream& in, char c) {
  unsigned count = 1;
  char c2;
  while ((in >> c2) && (c2 == c)) ++count;
  in.unget();
  return count;
}

static void translateBf(istream& in, disarm64::Assembler& as)
{
  using namespace disarm64;
  auto putcharPtr = DA_GP(19), getcharPtr = DA_GP(20), stackPtr = DA_GP(21), tmp = DA_GP(22);
  constexpr int saveSize = 48;
  as.add(STPx_pre(x29, x30, sp, -saveSize));
  as.add(STPx(putcharPtr, getcharPtr, sp, 16));
  as.add(STRxu(stackPtr, sp, 32));
  as.add(MOVx(putcharPtr, x0));
  as.add(MOVx(getcharPtr, x1));
  as.add(MOVx(stackPtr, x2));

  auto add = [&](GReg a, GReg b, int64_t imm) {
    if (auto op = ADDxi(a,b,imm)) {
      as.add(op);
    } else {
      as.movConst(tmp, imm);
      as.add(ADDx(a,b,tmp));
    }
  };
  auto sub = [&](GReg a, GReg b, int64_t imm) {
    if (auto op = SUBxi(a,b,imm)) {
      as.add(op);
    } else {
      as.movConst(tmp, imm);
      as.add(SUBx(a,b,tmp));
    }
  };

  vector<pair<Label, Label>> loops;
  char c;
  while (in >> c) {
    switch (c) {
      case '+':
        as.add(LDRxu(x0, stackPtr, 0));
        add(x0,x0,countRun(in, c));
        as.add(STRxu(x0, stackPtr, 0));
        break;
      case '-':
        as.add(LDRxu(x0, stackPtr, 0));
        sub(x0,x0,countRun(in, c));
        as.add(STRxu(x0, stackPtr, 0));
        break;
      case '>': add(stackPtr, stackPtr, countRun(in,c)*sizeof(uint64_t)); break;
      case '<': sub(stackPtr, stackPtr, countRun(in,c)*sizeof(uint64_t)); break;
      case '.':
        as.add(LDRxu(x0, stackPtr, 0));
        as.add(BLR(putcharPtr));
        break;
      case ',':
        as.add(BLR(getcharPtr));
        as.add(STRxu(x0, stackPtr, 0));
        break;
      case '[': {
        Label B = as.newLabel();
        as.placeLabel(B);
        as.add(LDRxu(x0, stackPtr, 0));
        as.add(CMPxi(x0, 0));
        Label F = as.newLabel();
        as.addBranch([](int32_t diff) { return BCOND(DA_EQ, diff); }, F);
        loops.push_back({B, F});
        break;
      }
      case ']': {
        auto top = loops.back();
        auto [B,F]=top;
        loops.pop_back();
        as.addBranch([](int32_t diff) { return disarm64::B(diff); }, B);
        as.placeLabel(F);
        break;
      }
      default: break;
    }
  }
  as.add(LDRxu(stackPtr, sp, 16+16));
  as.add(LDPx(putcharPtr, getcharPtr, sp, 16));
  as.add(LDPx_post(x29, x30, sp, saveSize));
  as.add(RET(x30));
}

int main(int argc, char* argv[]) {
  ofstream out;
  bool doDump=false;
  char** args = argv+1, **argLimit = argv+argc;
  if ((args<argLimit)&&(args[0]=="--dump"sv)) {
    out=ofstream("test-assembler.s");
    out << ".cfi_sections .eh_frame" << endl
        << ".globl _bf" << endl
        << ".type _bf, @function" << endl
        << ".p2align 4" << endl
        << ".cfi_startproc" << endl
	<< "_bf:" << endl;
    doDump=true;
    ++args;
  }
  if (args>=argLimit) {
    cerr << argv[0] << " filename.bf" << endl;
    return 1;
  }
  disarm64::Assembler assembler;
  disarm64::AssemblerWriter writer([&out](string_view str) { out << str; });
  if (doDump) assembler.setWriter(&writer);

  ifstream in(args[0]);
  translateBf(in, assembler);

  using FuncType = void(*)(int(*)(int), int(*)(),void*);
  auto func = reinterpret_cast<FuncType>(assembler.ready());
  if (doDump) {
     out << ".cfi_endproc" << endl
         << ".size _bf, .-_bf" << endl
         << ".section .note.GNU-stack,\"\",@progbits" << endl;
     out.flush();
     out.close();
     system("gcc -shared -fPIC -g -march=armv8.1-a+crc -o test-assembler.so test-assembler.s");
     auto lib = dlopen("./test-assembler.so", RTLD_NOW);
     func = reinterpret_cast<FuncType>(dlsym(lib, "_bf"));
     assembler.dump();
  }
  static int64_t stack[128 * 1024];
  func(&putchar, &getchar, stack);
}

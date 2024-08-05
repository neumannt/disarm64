#include "assembler.hpp"
#include "disarm64.hpp"
#include <sys/mman.h>
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>

// Disarm — Fast AArch64 Decode/Encoder
// SPDX-License-Identifier: BSD-3-Clause

using namespace std;

namespace disarm64 {

AssemblerWriter::AssemblerWriter(Callback callback)
    : callback(std::move(callback))
// Constructor
{}

AssemblerWriter::~AssemblerWriter()
// Destructor
{}

static char* writeLabelRaw(char* writer, uint32_t label, bool proxy)
// Helper for emitting labels
{
  *(writer++) = '.';
  *(writer++) = 'L';
  if (proxy)
    *(writer++) = 'L';
  if (!label) {
    *(writer++) = '0';
  } else {
    auto begin = writer;
    while (label) {
      *(writer++) = '0' + (label % 10);
      label /= 10;
    }
    reverse(begin, writer);
  }
  return writer;
}

void AssemblerWriter::writeLabel(uint32_t label, bool proxy)
// Write a label
{
  char buffer[128];
  auto writer = writeLabelRaw(buffer, label, proxy);
  *(writer++) = ':';
  *(writer++) = '\n';
  callback(string_view(buffer, writer - buffer));
}

void AssemblerWriter::writeOp(uint32_t op)
// Write an instruction
{
  char buffer[128];
  disarm64::Da64Inst ddi;
  disarm64::da64_decode(op, &ddi);
  disarm64::da64_format(&ddi, buffer);
  char* writer = buffer + strlen(buffer);
  *(writer++) = '\n';
  callback(string_view(buffer, writer - buffer));
};

void AssemblerWriter::writeBranch(uint32_t op, uint32_t label, bool proxy)
// Write a branch instruction
{
  char buffer[128];
  disarm64::Da64Inst ddi;
  disarm64::da64_decode(op, &ddi);
  disarm64::da64_format(&ddi, buffer);
  char* writer = buffer + strlen(buffer);
  while ((writer > buffer) && (writer[-1] != ' '))
    --writer;
  writer = writeLabelRaw(writer, label, proxy);
  *(writer++) = '\n';
  callback(string_view(buffer, writer - buffer));
}

Assembler::Assembler()
// Constructor
{}

Assembler::~Assembler()
// Destructor
{
  if (executableCode)
    munmap(executableCode, executableCodeLimit - executableCode);
}

void Assembler::dump()
// Dump generated code (for debugging)
{
  flushJumpThunks(false);
  char buffer[128];
  for (auto op : code) {
    ios_base::fmtflags flags = cerr.setf(ios_base::hex, ios_base::basefield);
    char fill = cerr.fill('0');
    cerr << std::setw(4) << op;
    cerr.fill(fill);
    cerr.setf(flags, std::ios_base::basefield);
    disarm64::Da64Inst ddi;
    disarm64::da64_decode(op, &ddi);
    disarm64::da64_format(&ddi, buffer);
    cerr << " " << buffer << endl;
  }
}

void* Assembler::ready()
// Prepare for execution
{
  flushJumpThunks(false);
  assert(!executableCode);
  static constexpr uint64_t pageSize = 4096;
  uint64_t usedSize = code.size() * sizeof(uint32_t);
  uint64_t size = (usedSize + pageSize - 1) & (~(pageSize - 1));
#if !defined(MAP_ANON) && !defined(MAP_ANONYMOUS)
  int fd = open("/dev/zero", O_RDWR);
  if (fd < 0)
    return nullptr;

  void* p = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  close(fd);
#else
  void* p = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
  if ((p == MAP_FAILED) || (!p))
    return nullptr;
  __builtin_memcpy(p, code.data(), usedSize);
  executableCode = static_cast<byte*>(p);
  executableCodeLimit = executableCode + size;
  if (mprotect(executableCode, size, PROT_READ | PROT_EXEC) != 0)
    return nullptr;
  return executableCode;
}

void* Assembler::resolveLabel(Label label)
// Get the address of a label (after calling ready)
{
  auto info = labels[label.getId()];
  if ((!executableCode) || (!(info & 1)))
    return nullptr;
  return executableCode + ((info >> 1) * sizeof(uint32_t));
}

pair<void*, size_t> Assembler::release()
// Release the allocated code. Must be freed with munmap
{
  return pair<void*, size_t>(executableCode,
                             executableCodeLimit - executableCode);
}

static inline int32_t getJumpDelta(int64_t source, int64_t target)
// Compute the jump size in bytes
{
  int64_t delta = target - source;
  assert(int64_t(int32_t(delta)) == delta);
  return delta;
}

static inline size_t getJumpDeadline(unsigned source,
                                     Assembler::MaximumDistance max)
// Compute the deadline for a jump instruction
{
  return size_t(source) +
         ((max == Assembler::MaximumDistance::J1MB)
              ? ((1ul << 18) - 1)
              : ((max == Assembler::MaximumDistance::J32KB) ? ((1ul << 13) - 1)
                                                            : (1ul << 25) - 1));
}

size_t Assembler::PendingLabel::getDeadline() const
// Compute the deadline for placing this branch
{
  return getJumpDeadline(offset, maxDistance);
}

static inline Assembler::MaximumDistance
identifyMaximumDistance(Assembler::JumpEncoder& encoder)
// Identify the maximum distance of a branch
{
  if (encoder((1 << 25) - 1))
    return Assembler::MaximumDistance::J128MB;
  if (encoder((1 << 18) - 1))
    return Assembler::MaximumDistance::J1MB;
  assert(encoder((1 << 11) - 1) && "invalid branch");
  return Assembler::MaximumDistance::J32KB;
}

void Assembler::combineDeadlines()
// Combine deadlines from pending and out of reach list
{
  auto oor = outOfReachList.size();
  auto dp =
      (oor > flushDeadlinePendingLabels) ? 0 : flushDeadlinePendingLabels - oor;
  flushDeadline = min(flushDeadlineOutOfReach, dp);
}

Label Assembler::newLabel()
// Create a new label
{
  labels.push_back(0);
  return Label(labels.size() - 1);
}

void Assembler::placeLabel(Label label)
// Place a label
{
  size_t ofs = code.size();
  auto info = labels[label.getId()];
  assert(!(info & 1));
  if (writer) [[unlikely]]
    writer->writeLabel(label.getId(), false);

  // Place all outstanding labels
  bool needsUpdate = false;
  for (auto iter = info >> 1; iter;) {
    auto& p = pendingLabels[iter - 1];
    ssize_t disp = ssize_t(ofs - p.offset);
    auto op = p.encoder(disp);

    // Remove from pending queue
    unsigned jc = unsigned(p.maxDistance);
    if (p.prevInClass) {
      pendingLabels[p.prevInClass - 1].nextInClass = p.nextInClass;
    } else {
      pendingLabelQueue[jc].first = p.nextInClass;
      needsUpdate = true;
    }
    if (p.nextInClass) {
      pendingLabels[p.nextInClass - 1].prevInClass = p.prevInClass;
    } else {
      pendingLabelQueue[jc].last = p.prevInClass;
    }

    // The target must be in range, otherwise we would have flushed the jump
    // already
    assert(op);
    if (writer) [[unlikely]]
      writer->writeLabel(p.offset, true);
    code[p.offset] = op;

    auto n = p.next >> 1;
    p.next = nextPendingLabel;
    nextPendingLabel = iter;
    iter = n;
  }
  if (needsUpdate)
    recomputeDeadlines();

  // Remember the position
  labels[label.getId()] = (ofs << 1) | 1;
}

void Assembler::add(uint32_t op)
// Add an instruction
{
  assert(op && "invalid encoding");
  code.push_back(op);
  if (writer) [[unlikely]]
    writer->writeOp(op);
  if (needsFlush()) [[unlikely]]
    flushJumpThunks(false);
}

void Assembler::addBranch(JumpEncoder encoder, Label target)
// Add a branch instruction
{
  // Identify the maximum branch distance
  MaximumDistance maximumDistance = identifyMaximumDistance(encoder);

  // Do we know the target already?
  unsigned targetId = target.getId();
  if (labels[targetId] & 1) {
    int32_t delta = getJumpDelta(code.size(), labels[targetId] >> 1);
    // Can we simply encode the instruction?
    if (auto op = encoder(delta)) {
      code.push_back(op);
      if (writer) [[unlikely]]
        writer->writeBranch(op, target.getId(), false);

      if (maximumDistance == MaximumDistance::J128MB)
        flushJumpThunks(true);
      return;
    }
    assert(maximumDistance != MaximumDistance::J128MB);

    // No, encode a jump to a jump thunk instead
    unsigned jumpPos = code.size();
    auto op = encoder(4);
    code.push_back(op);
    outOfReachList.push_back({jumpPos, targetId, std::move(encoder)});
    flushDeadlineOutOfReach =
        min(flushDeadlineOutOfReach, getJumpDeadline(jumpPos, maximumDistance));
    combineDeadlines();
    if (writer) [[unlikely]]
      writer->writeBranch(op, jumpPos, true);
    if (needsFlush()) [[unlikely]]
      flushJumpThunks(false);
    return;
  }

  // Create a pending jump
  unsigned jumpPos = code.size();
  auto op = encoder(4);
  addUndefinedLabel(std::move(encoder), code.size(), target, maximumDistance);
  code.push_back(op);
  if (writer) [[unlikely]]
    writer->writeBranch(op, jumpPos, true);

  // Trigger flush if needed
  if (maximumDistance == MaximumDistance::J128MB) {
    flushJumpThunks(true);
  } else if (needsFlush()) [[unlikely]]
    flushJumpThunks(false);
}

void Assembler::emitJumpTable(Label start, std::span<Label> table)
// Create a jump table
{
  // Make sure we have safely dump the table
  flushJumpThunks(false, table.size());

  // Place the start
  placeLabel(start);
  auto tableStart = code.size();
  int32_t shift = 0;
  for (auto target : table) {
    auto targetId = target.getId();
    if (labels[targetId] & 1) {
      int32_t delta = getJumpDelta(tableStart, labels[targetId] >> 1);
      code.push_back(delta);
    } else {
      addUndefinedLabel([shift](int32_t delta) { return delta + shift; },
                        code.size(), target, MaximumDistance::J128MB);
      code.push_back(0);
    }
    if (writer) [[unlikely]] {
      char buffer[128];
      snprintf(buffer, sizeof(buffer), ".word (.L%u-.L%u)>>2\n",
               unsigned(targetId), unsigned(start.getId()));
      writer->writeRaw(buffer);
    }
    ++shift;
  }
}

void Assembler::recomputeDeadlines()
// Recompute deadlines after a queue head has changed
{
  unsigned instructionsInFront = 0;
  uintptr_t queueDeadline = noDeadline;
  for (unsigned index = 0; index != 3; ++index)
    if (pendingLabelQueue[index].first) {
      queueDeadline =
          min(queueDeadline,
              getJumpDeadline(
                  pendingLabels[pendingLabelQueue[index].first - 1].offset,
                  MaximumDistance(index)));
      ++instructionsInFront;
    }
  flushDeadlinePendingLabels = (instructionsInFront > queueDeadline)
                                   ? 0
                                   : (queueDeadline - instructionsInFront);
  combineDeadlines();
}

void Assembler::flushJumpThunks(bool afterUnconditionalBranch,
                                size_t pendingBlockSize)
// Flush jump thunks
{
  // We add 1KB extra buffer in front of the deadline to avoid repeated jump
  // thunk generation
  static constexpr size_t gracePeriod = (1 << 10) / 4;

  // Do we have anything to do?
  if (outOfReachList.empty() &&
      (code.size() + gracePeriod + pendingBlockSize < flushDeadline))
    return;

  // Add an unconditional branch to jump over the thunks (unless we have one in
  // front)
  auto jumpLocation = code.size();
  auto B = [](ptrdiff_t imm26) -> unsigned {
    return (0x14000000) | ((imm26) << 0 & 0x3ffffff);
  };
  if (!afterUnconditionalBranch) {
    auto op = B(0);
    code.push_back(op);
    if (writer) [[unlikely]]
      writer->writeBranch(op, jumpLocation, true);
  }

  // Emit all out of reach branches
  for (auto& b : outOfReachList) {
    // Generate a long range outgoing jump
    auto thunkPosition = code.size();
    ssize_t labelOffset = ssize_t((labels[b.target] >> 1) - thunkPosition);

    auto op = B(labelOffset);
    code.push_back(op);
    if (writer) [[unlikely]] {
      writer->writeLabel(b.jump, true);
      writer->writeBranch(op, b.target, false);
    }

    // And update the short range incoming jump
    labelOffset = ssize_t(thunkPosition - b.jump);
    op = b.encoder(labelOffset);
    assert(op);
    code[b.jump] = op;
  }
  outOfReachList.clear();
  flushDeadlineOutOfReach = noDeadline;

  // Convert pending branches with unknown target into long jumps, too, if we
  // run out of time.
  static constexpr unsigned class128MB = unsigned(MaximumDistance::J128MB);
  static constexpr unsigned classCount = class128MB + 1;
  while (true) {
    // We place  branches in the order of their deadline because each emit
    // advances the code address by one
    unsigned nextInQueue = 0;
    while ((nextInQueue < classCount) &&
           (!pendingLabelQueue[nextInQueue].first))
      ++nextInQueue;
    if (nextInQueue == classCount)
      break;
    for (unsigned index = nextInQueue + 1; index != classCount; ++index)
      if (pendingLabelQueue[index].first &&
          pendingLabels[pendingLabelQueue[index].first - 1].getDeadline() <
              pendingLabels[pendingLabelQueue[nextInQueue].first - 1]
                  .getDeadline())
        nextInQueue = index;

    // Check if we can wait with emitting that branch
    auto bid = pendingLabelQueue[nextInQueue].first;
    auto& b = pendingLabels[bid - 1];
    if (b.getDeadline() > code.size() + gracePeriod + pendingBlockSize)
      break;

    // We have a problem when we run out of range for conditional branches. We
    // could use a br instruction, but that would require having a free register
    // available. For now, we just report an error.
    assert(nextInQueue != class128MB);

    // This will be patched when the target becomes known
    auto thunkPosition = code.size();
    code.push_back(B(4));
    if (writer) [[unlikely]] {
      writer->writeLabel(b.offset, true);
      writer->writeBranch(B(4), b.id, false);
    }

    // Update the coming jump
    ssize_t labelOffset = (thunkPosition - b.offset);
    auto op = b.encoder(labelOffset);
    assert(op);
    code[b.offset] = op;

    // Remember that we have to update the thunk now
    b.maxDistance = MaximumDistance::J128MB;
    b.offset = thunkPosition;
    b.encoder = B;

    // Update the queue
    pendingLabelQueue[nextInQueue].first = b.nextInClass;
    if (b.nextInClass)
      pendingLabels[b.nextInClass - 1].prevInClass = 0;
    else
      pendingLabelQueue[nextInQueue].last = 0;
    b.nextInClass = 0;
    b.prevInClass = pendingLabelQueue[class128MB].last;
    if (b.prevInClass)
      pendingLabels[b.prevInClass - 1].nextInClass = bid;
    else
      pendingLabelQueue[class128MB].first = bid;
    pendingLabelQueue[class128MB].last = bid;
  }

  // Recompute the deadlines
  recomputeDeadlines();

  // Update the jump over the thunks (if any)
  if (!afterUnconditionalBranch) {
    ssize_t labelOffset = (code.size() - jumpLocation);
    auto op = B(labelOffset);
    assert(op);
    code[jumpLocation] = op;
    if (writer) [[unlikely]]
      writer->writeLabel(jumpLocation, true);
  }
}

void Assembler::addUndefinedLabel(JumpEncoder encoder, unsigned jumpPos,
                                  Label target, MaximumDistance maximumDistance)
// Create an undefined label
{
  auto maxDistance = identifyMaximumDistance(encoder);

  PendingLabel p;
  p.id = target.getId();
  p.next = labels[p.id];
  p.offset = jumpPos;
  p.encoder = std::move(encoder);
  p.maxDistance = maximumDistance;

  unsigned slot;
  if (nextPendingLabel) {
    slot = nextPendingLabel;
    unsigned n = pendingLabels[slot - 1].next;
    pendingLabels[slot - 1] = std::move(p);
    nextPendingLabel = n;
  } else {
    pendingLabels.push_back(std::move(p));
    slot = pendingLabels.size();
  }
  labels[p.id] = slot << 1;

  // Update deadlines
  unsigned gapClass = unsigned(maxDistance);
  if (pendingLabelQueue[gapClass].first) {
    pendingLabels[slot - 1].prevInClass = pendingLabelQueue[gapClass].last;
    pendingLabels[pendingLabelQueue[gapClass].last - 1].nextInClass = slot;
  } else {
    pendingLabelQueue[gapClass].first = pendingLabelQueue[gapClass].last = slot;
    recomputeDeadlines();
  }
}

void Assembler::movConst(GReg reg, uint64_t val)
// Move a constant into a register
{
  uint32_t buffer[4];
  unsigned len = MOVconst(buffer, reg, val);
  for (unsigned index = 0; index != len; ++index)
    add(buffer[index]);
}

Assembler::PatchablePosition Assembler::patchableMovConst32(GReg reg)
// Move a constant into a register in a way that can be changed later.
{
  PatchablePosition result(code.size(), reg.val);
  code.push_back(MOVZw(reg, 0x5678));
  code.push_back(MOVKw_shift(reg, 0x1234, 1));
  if (writer) [[unlikely]] {
    char buffer[128];
    snprintf(buffer, sizeof(buffer), "mov w%u, const%ulow\n", unsigned(reg.val),
             unsigned(result.pos));
    writer->writeRaw(buffer);
    snprintf(buffer, sizeof(buffer), "movk w%u, const%uhigh, lsl #16\n",
             unsigned(reg.val), unsigned(result.pos));
    writer->writeRaw(buffer);
  }
  return result;
}

void Assembler::patchMovConst32(PatchablePosition pos, uint32_t value)
// Patch the adjustment
{
  auto reg = GReg(pos.reg);
  code[pos.pos] = MOVZw(reg, value & 0xFFFF);
  code[pos.pos + 1] = MOVKw_shift(reg, value >> 16, 1);
  if (writer) [[unlikely]] {
    char buffer[128];
    snprintf(buffer, sizeof(buffer), "const%ulow=%u\n", unsigned(pos.pos),
             unsigned(value & 0xFFFF));
    writer->writeRaw(buffer);
    snprintf(buffer, sizeof(buffer), "const%uhigh=%u\n", unsigned(pos.pos),
             unsigned(value >> 16));
    writer->writeRaw(buffer);
  }
}

}

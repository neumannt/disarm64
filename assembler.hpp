#ifndef DA_ASSEMBLER_H_
#define DA_ASSEMBLER_H_

// Disarm — Fast AArch64 Decode/Encoder
// SPDX-License-Identifier: BSD-3-Clause

#include <cstdint>
#include <functional>
#include <vector>

namespace disarm64 {

struct GReg;
class Assembler;

/// A label for jumps
class Label {
  /// The id
  unsigned id;

  /// Constructor
  Label(unsigned id) : id(id) {}

  friend class Assembler;

public:
  /// Get the id
  unsigned getId() const { return id; }
};

/// Helper class for collecting assembler output
class AssemblerWriter {
public:
  /// The writer callback
  using Callback = std::move_only_function<void(const char*, uintptr_t)>;

private:
  /// The target
  Callback callback;

public:
  /// Constructor
  AssemblerWriter(Callback callback);
  /// Destructor
  ~AssemblerWriter();
  /// Write a label
  void writeLabel(uint32_t label, bool proxy);
  /// Write an instruction
  void writeOp(uint32_t op);
  /// Write a branch instruction
  void writeBranch(uint32_t op, uint32_t label, bool proxy);
};

/// High level interface for generating assembler code
class Assembler {
public:
  /// Encoding logic for jumps
  using JumpEncoder = std::move_only_function<uint32_t(int32_t)>;
  /// Maximum distance of a branch
  enum class MaximumDistance { J32KB, J1MB, J128MB };

private:
  /// Marker for no deadline
  static constexpr size_t noDeadline = ~size_t(0);

  /// The generate code
  std::vector<uint32_t> code;
  /// The assembler writer (if any)
  AssemblerWriter* writer = nullptr;
  /// The executable code
  std::byte *executableCode = nullptr, *executableCodeLimit = nullptr;
  /// All labels
  std::vector<uintptr_t> labels;
  /// A pending label position
  struct PendingLabel {
    /// The next pending label
    unsigned next;
    /// The label
    unsigned id;
    /// The position
    size_t offset;
    /// The encoder
    JumpEncoder encoder;
    /// Queue management
    unsigned prevInClass = 0, nextInClass = 0;
    /// The maximum distance class
    MaximumDistance maxDistance;

    /// Compute the deadline for placing this branch
    inline size_t getDeadline() const;
  };
  /// An out-of-reach jump
  struct OutOfReachJump {
    /// The jump position
    size_t jump;
    /// The target
    size_t target;
    /// The encoder
    JumpEncoder encoder;
  };
  /// All pending labels
  std::vector<PendingLabel> pendingLabels;
  /// The next free pending label spot
  unsigned nextPendingLabel = 0;
  /// A queue of pending labels
  struct PendingLabelQueue {
    unsigned first = 0, last = 0;
  };
  /// The pending label queues, categorized by distance, sorted by source
  std::array<PendingLabelQueue, 3> pendingLabelQueue;
  /// The out of reach jumps
  std::vector<OutOfReachJump> outOfReachList;
  /// The deadline for flushing out of reach jump instructions
  size_t flushDeadlineOutOfReach = noDeadline;
  /// The deadline for flushing the pending labels
  size_t flushDeadlinePendingLabels = noDeadline;
  /// The deadline for any jump instructions
  size_t flushDeadline = noDeadline;

  /// Do we have to flush jump thunks?
  bool needsFlush() const { return code.size() >= flushDeadline; }
  /// Combine deadlines from pending and out of reach list
  inline void combineDeadlines();
  /// Recompute deadlines after a queue head has changed
  void recomputeDeadlines();
  /// Flush jump thunks
  void flushJumpThunks(bool afterUnconditionalBranch);
  /// Add an undefined label
  void addUndefinedLabel(JumpEncoder encoder, unsigned jumpPos, Label target,
                         MaximumDistance maximumDistance);

public:
  /// Constructor
  Assembler();
  /// Destructor
  ~Assembler();

  /// Install an assembler writer
  void setWriter(AssemblerWriter* out) { writer = out; }
  /// Dump generated code (for debugging)
  void dump();
  /// Prepare for execution
  void* ready();
  /// Release the allocated code. Must be freed with munmap
  std::pair<void*, size_t> release();

  /// Create a new label
  Label newLabel();
  /// Place a label
  void placeLabel(Label label);

  /// Add an instruction
  void add(uint32_t instruction);
  /// Add a branch instruction
  void addBranch(JumpEncoder encoder, Label target);
  /// Move a constant into a register
  void movConst(GReg reg, uint64_t val);
};

}

#endif

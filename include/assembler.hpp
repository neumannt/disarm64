#ifndef DA_ASSEMBLER_H_
#define DA_ASSEMBLER_H_

// Disarm — Fast AArch64 Decode/Encoder
// SPDX-License-Identifier: BSD-3-Clause

#include <cstdint>
#include <functional>
#include <span>
#include <string_view>
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
  /// Constructor
  constexpr Label() : id(0) {}

  /// Get the id
  unsigned getId() const { return id; }
};

/// Helper class for collecting assembler output
class AssemblerWriter {
public:
  // Workaround for incomplete C++23 support
#ifdef __cpp_lib_move_only_function
  /// The writer callback
  using Callback = std::move_only_function<void(std::string_view)>;
#else
  /// The writer callback
  using Callback = std::function<void(std::string_view)>;
#endif

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
  /// Write a raw string
  void writeRaw(std::string_view str) { callback(str); }
};

/// High level interface for generating assembler code
class Assembler {
public:
// Workaround for incomplete C++23 support
#ifdef __cpp_lib_move_only_function
  /// Encoding logic for jumps
  using JumpEncoder = std::move_only_function<uint32_t(int32_t)>;
#else
  /// Encoding logic for jumps
  using JumpEncoder = std::function<uint32_t(int32_t)>;
#endif
  /// Maximum distance of a branch
  enum class MaximumDistance : uint8_t { J32KB, J1MB, J128MB };
  /// A patchable position
  class PatchablePosition {
    size_t pos;
    unsigned reg;

    PatchablePosition(size_t pos, unsigned reg) : pos(pos), reg(reg) {}
    friend class Assembler;
  };

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
  /// The different types of pending labels
  enum class PendingLabelCategory : uint8_t { Encoder, AdrNear, AdrFar };
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
    /// The category of pending label
    PendingLabelCategory category;

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
  void flushJumpThunks(bool afterUnconditionalBranch,
                       size_t pendingBlockSize = 0);
  /// Add an undefined label
  void addUndefinedLabel(JumpEncoder encoder, unsigned jumpPos, Label target,
                         PendingLabelCategory cat,
                         MaximumDistance maximumDistance);

public:
  /// Constructor
  Assembler();
  /// Destructor
  ~Assembler();

  /// Install an assembler writer
  void setWriter(AssemblerWriter* out) { writer = out; }
  /// Get the assembler writer (if any)
  AssemblerWriter* getWriter() const { return writer; }
  /// Dump generated code (for debugging)
  void dump();
  /// Prepare for execution
  void* ready();
  /// Get the address of a label (after calling ready)
  void* resolveLabel(Label label);
  /// Release the allocated code. Must be freed with munmap
  std::pair<void*, size_t> release();
  /// Get the current code size
  size_t getSize() const { return code.size() * sizeof(uint32_t); }

  /// Create a new label
  [[nodiscard]] Label newLabel();
  /// Place a label
  void placeLabel(Label label);

  /// Add an instruction
  void add(uint32_t instruction);
  /// Add a branch instruction
  void addBranch(JumpEncoder encoder, Label target);
  /// Create a jump table
  void emitJumpTable(Label start, std::span<Label> table);
  /// Embed data inside the generated code
  void embed(Label start, const void* data, unsigned len,
             unsigned alignment = 0);
  /// Move a constant into a register
  void movConst(GReg reg, uint64_t val);
  /// Load the address of a label into a register
  void adr(GReg reg, Label label, bool maxDistance1MB = false);

  /// Move a constant into a register in a way that can be changed later.
  /// This is intended for sp adjustment in the function prologue.
  [[nodiscard]] PatchablePosition patchableMovConst32(GReg reg);
  /// Patch the adjustment
  void patchMovConst32(PatchablePosition, uint32_t value);
};

}

#endif

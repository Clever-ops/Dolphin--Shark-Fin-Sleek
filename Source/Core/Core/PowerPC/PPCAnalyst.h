// Copyright 2008 Dolphin Emulator Project
// Licensed under GPLv2+
// Refer to the license.txt file included.

#pragma once

#include <algorithm>
#include <cstddef>
#include <set>
#include <vector>

#include "Common/BitSet.h"
#include "Common/CommonTypes.h"
#include "Core/PowerPC/PPCTables.h"

class PPCSymbolDB;

namespace Common
{
struct Symbol;
}

namespace PPCAnalyst
{
struct CodeOp  // 16B
{
  UGeckoInstruction inst;
  GekkoOPInfo* opinfo;
  u32 address;
  u32 branchTo;       // if 0, not a branch
  int branchToIndex;  // index of target block
  BitSet32 regsOut;
  BitSet32 regsIn;
  BitSet32 fregsIn;
  s8 fregOut;
  bool isBranchTarget;
  bool wantsCR0;
  bool wantsCR1;
  bool wantsFPRF;
  bool wantsCA;
  bool wantsCAInFlags;
  bool outputCR0;
  bool outputCR1;
  bool outputFPRF;
  bool outputCA;
  bool canEndBlock;
  bool skipLRStack;
  bool skip;  // followed BL-s for example
  // which registers are still needed after this instruction in this block
  BitSet32 fprInUse;
  BitSet32 gprInUse;
  // just because a register is in use doesn't mean we actually need or want it in an x86 register.
  BitSet32 gprInReg;
  // we do double stores from GPRs, so we don't want to load a PowerPC floating point register into
  // an XMM only to move it again to a GPR afterwards.
  BitSet32 fprInXmm;
  // which registers will be overwritten by future instructions in this block
  // (assuming we do not terminate early)
  BitSet32 fprWillBeSet;
  BitSet32 gprWillBeSet;
  // whether an fpr is known to be an actual single-precision value at this point in the block.
  BitSet32 fprIsSingle;
  // whether an fpr is known to have identical top and bottom halves (e.g. due to a single
  // instruction)
  BitSet32 fprIsDuplicated;
  // whether an fpr is the output of a single-precision arithmetic instruction, i.e. whether we can
  // safely
  // skip PPC_FP.
  BitSet32 fprIsStoreSafe;
};

struct BlockStats
{
  bool isFirstBlockOfFunction;
  bool isLastBlockOfFunction;
  int numCycles;
};

struct BlockRegStats
{
  short firstRead[32];
  short firstWrite[32];
  short lastRead[32];
  short lastWrite[32];
  short numReads[32];
  short numWrites[32];

  bool any;
  bool anyTimer;

  int GetTotalNumAccesses(int reg) const { return numReads[reg] + numWrites[reg]; }
  int GetUseRange(int reg) const
  {
    return std::max(lastRead[reg], lastWrite[reg]) - std::min(firstRead[reg], firstWrite[reg]);
  }

  bool IsUsed(int reg) const { return (numReads[reg] + numWrites[reg]) > 0; }
  void SetInputRegister(int reg, short opindex)
  {
    if (firstRead[reg] == -1)
      firstRead[reg] = opindex;
    lastRead[reg] = opindex;
    numReads[reg]++;
  }

  void SetOutputRegister(int reg, short opindex)
  {
    if (firstWrite[reg] == -1)
      firstWrite[reg] = opindex;
    lastWrite[reg] = opindex;
    numWrites[reg]++;
  }

  void Clear()
  {
    for (int i = 0; i < 32; ++i)
    {
      firstRead[i] = -1;
      firstWrite[i] = -1;
      numReads[i] = 0;
      numWrites[i] = 0;
    }
  }
};

using CodeBuffer = std::vector<CodeOp>;

struct CodeBlock
{
  // Beginning PPC address.
  u32 m_address;

  // Number of instructions
  // Gives us the size of the block.
  u32 m_num_instructions;

  // Some basic statistics about the block.
  BlockStats* m_stats;

  // Register statistics about the block.
  BlockRegStats *m_gpa, *m_fpa;

  // Are we a broken block?
  bool m_broken;

  // Did we have a memory_exception?
  bool m_memory_exception;

  // Which GQRs this block uses, if any.
  BitSet8 m_gqr_used;

  // Which GQRs this block modifies, if any.
  BitSet8 m_gqr_modified;

  // Which registers this block reads from before defining, if any, in order of them being read.
  // 0-31: GPRs r0-r31
  // 32-63: FPRs fp0-fp31
  std::vector<s8> m_inputs;

  // Which memory locations are occupied by this block.
  std::set<u32> m_physical_addresses;
};

class PPCAnalyzer
{
public:
  enum AnalystOption
  {
    // Conditional branch continuing
    // If the JIT core supports conditional branches within the blocks
    // Block will end on unconditional branch or other ENDBLOCK flagged instruction.
    // Requires JIT support to be enabled.
    OPTION_CONDITIONAL_CONTINUE = (1 << 0),

    // Try to inline unconditional branches/calls/returns.
    // Also track the LR value to follow unconditional return instructions.
    // Might require JIT intervention to support it correctly.
    // Especially if the BLR optimization is used.
    OPTION_BRANCH_FOLLOW = (1 << 1),

    // Complex blocks support jumping backwards on to themselves.
    // Happens commonly in loops, pretty complex to support.
    // May require register caches to use register usage metrics.
    // XXX: NOT COMPLETE
    OPTION_COMPLEX_BLOCK = (1 << 2),

    // Similar to complex blocks.
    // Instead of jumping backwards, this jumps forwards within the block.
    // Requires JIT support to work.
    // XXX: NOT COMPLETE
    OPTION_FORWARD_JUMP = (1 << 3),

    // Reorder compare/Rc instructions next to their associated branches and
    // merge in the JIT (for common cases, anyway).
    OPTION_BRANCH_MERGE = (1 << 4),

    // Reorder carry instructions next to their associated branches and pass
    // carry flags in the x86 flags between them, instead of in XER.
    OPTION_CARRY_MERGE = (1 << 5),

    // Reorder cror instructions next to their associated fcmp.
    OPTION_CROR_MERGE = (1 << 6),
  };

  // Option setting/getting
  void SetOption(AnalystOption option) { m_options |= option; }
  void ClearOption(AnalystOption option) { m_options &= ~(option); }
  bool HasOption(AnalystOption option) const { return !!(m_options & option); }
  u32 Analyze(u32 address, CodeBlock* block, CodeBuffer* buffer, std::size_t block_size);

private:
  enum class ReorderType
  {
    Carry,
    CMP,
    CROR
  };

  void ReorderInstructionsCore(u32 instructions, CodeOp* code, bool reverse, ReorderType type);
  void ReorderInstructions(u32 instructions, CodeOp* code);
  void SetInstructionStats(CodeBlock* block, CodeOp* code, const GekkoOPInfo* opinfo, u32 index);

  // Options
  u32 m_options = 0;
};

void LogFunctionCall(u32 addr);
void FindFunctions(u32 startAddr, u32 endAddr, PPCSymbolDB* func_db);
bool AnalyzeFunction(u32 startAddr, Common::Symbol& func, u32 max_size = 0);
bool ReanalyzeFunction(u32 start_addr, Common::Symbol& func, u32 max_size = 0);

}  // namespace PPCAnalyst

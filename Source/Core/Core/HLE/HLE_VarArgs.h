// Copyright 2017 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include "Common/Align.h"
#include "Common/CommonTypes.h"
#include "Common/Concepts.h"

#include "Core/PowerPC/MMU.h"
#include "Core/PowerPC/PowerPC.h"

#include <type_traits>

#include "Common/Future/CppLibConcepts.h"

namespace Core
{
class CPUThreadGuard;
class System;
}  // namespace Core

namespace HLE::SystemVABI
{
template <typename T>
concept arg_ARGPOINTER = Common::Union<T> || Common::Class<T>;
template <typename T>
concept arg_WORD = Common::Pointer<T> ||(std::integral<T> && sizeof(T) <= 4);
template <typename T>
concept arg_DOUBLEWORD = std::integral<T> && sizeof(T) == 8;
template <typename T>
concept arg_ARGREAL = std::floating_point<T>;

// See System V ABI (SVR4) for more details
//  -> 3-18 Parameter Passing
//  -> 3-21 Variable Argument Lists
//
// Source:
// http://refspecs.linux-foundation.org/elf/elfspec_ppc.pdf
class VAList
{
public:
  explicit VAList(Core::System& system, u32 stack, u32 gpr = 3, u32 fpr = 1, u32 gpr_max = 10,
                  u32 fpr_max = 8)
      : m_system(system), m_gpr(gpr), m_fpr(fpr), m_gpr_max(gpr_max), m_fpr_max(fpr_max),
        m_stack(stack)
  {
  }
  virtual ~VAList();

  template <arg_ARGPOINTER T>
  T GetArg(const Core::CPUThreadGuard& guard)
  {
    T obj;
    u32 addr = GetArg<u32>(guard);

    for (size_t i = 0; i < sizeof(T); i += 1, addr += 1)
    {
      reinterpret_cast<u8*>(&obj)[i] = PowerPC::MMU::HostRead_U8(guard, addr);
    }

    return obj;
  }

  template <arg_WORD T>
  T GetArg(const Core::CPUThreadGuard& guard)
  {
    static_assert(!std::is_pointer<T>(), "VAList doesn't support pointers");
    u64 value;

    if (m_gpr <= m_gpr_max)
    {
      value = GetGPR(guard, m_gpr);
      m_gpr += 1;
    }
    else
    {
      m_stack = Common::AlignUp(m_stack, 4);
      value = PowerPC::MMU::HostRead_U32(guard, m_stack);
      m_stack += 4;
    }

    return static_cast<T>(value);
  }

  template <arg_DOUBLEWORD T>
  T GetArg(const Core::CPUThreadGuard& guard)
  {
    u64 value;

    if (m_gpr % 2 == 0)
      m_gpr += 1;
    if (m_gpr < m_gpr_max)
    {
      value = static_cast<u64>(GetGPR(guard, m_gpr)) << 32 | GetGPR(guard, m_gpr + 1);
      m_gpr += 2;
    }
    else
    {
      m_stack = Common::AlignUp(m_stack, 8);
      value = PowerPC::MMU::HostRead_U64(guard, m_stack);
      m_stack += 8;
    }

    return static_cast<T>(value);
  }

  template <arg_ARGREAL T>
  T GetArg(const Core::CPUThreadGuard& guard)
  {
    double value;

    if (m_fpr <= m_fpr_max)
    {
      value = GetFPR(guard, m_fpr);
      m_fpr += 1;
    }
    else
    {
      m_stack = Common::AlignUp(m_stack, 8);
      value = PowerPC::MMU::HostRead_F64(guard, m_stack);
      m_stack += 8;
    }

    return static_cast<T>(value);
  }

  // Helper
  template <typename T>
  T GetArgT(const Core::CPUThreadGuard& guard)
  {
    return static_cast<T>(GetArg<T>(guard));
  }

protected:
  Core::System& m_system;
  u32 m_gpr = 3;
  u32 m_fpr = 1;
  const u32 m_gpr_max = 10;
  const u32 m_fpr_max = 8;
  u32 m_stack;

private:
  virtual u32 GetGPR(const Core::CPUThreadGuard& guard, u32 gpr) const;
  virtual double GetFPR(const Core::CPUThreadGuard& guard, u32 fpr) const;
};

// See System V ABI (SVR4) for more details
//  -> 6-6 Required Routines
//  -> 3-21 Variable Argument Lists
//
// Source:
// http://refspecs.linux-foundation.org/elf/elfspec_ppc.pdf
class VAListStruct : public VAList
{
public:
  explicit VAListStruct(Core::System& system, const Core::CPUThreadGuard& guard, u32 address);
  ~VAListStruct() = default;

private:
  struct svr4_va_list
  {
    u8 gpr;
    u8 fpr;
    u32 overflow_arg_area;
    u32 reg_save_area;
  };
  const svr4_va_list m_va_list;
  const u32 m_address;
  const bool m_has_fpr_area;

  u32 GetGPRArea() const;
  u32 GetFPRArea() const;

  u32 GetGPR(const Core::CPUThreadGuard& guard, u32 gpr) const override;
  double GetFPR(const Core::CPUThreadGuard& guard, u32 fpr) const override;
};

}  // namespace HLE::SystemVABI

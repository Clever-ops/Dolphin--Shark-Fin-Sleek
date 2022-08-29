// Copyright 2013 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "Common/CPUDetect.h"

#include <cstring>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <thread>

#ifdef __APPLE__
#include <sys/sysctl.h>
#elif defined(_WIN32)
#include <Windows.h>
#include <arm64intr.h>
#else
#ifndef __FreeBSD__
#include <asm/hwcap.h>
#endif
#include <sys/auxv.h>
#endif

#include <fmt/format.h>

#include "Common/CommonTypes.h"
#include "Common/FileUtil.h"
#include "Common/StringUtil.h"

#if defined(__APPLE__) || defined(__FreeBSD__)

static std::optional<std::string> ReadSysctlByNameString(const char* name)
{
  std::string result;

  size_t result_len = 0;
  if (sysctlbyname(name, nullptr, &result_len, nullptr, 0))
    return std::nullopt;

  result.resize(result_len);
  if (sysctlbyname(name, result.data(), &result_len, nullptr, 0))
    return std::nullopt;

  TruncateToCString(&result);
  return result;
}

#endif

#if defined(_WIN32)

static constexpr char SUBKEY_CORE0[] = R"(HARDWARE\DESCRIPTION\System\CentralProcessor\0)";

// Identifier: human-readable version of CPUID
// ProcessorNameString: marketing name of the processor
// VendorIdentifier: vendor company name
// There are some other maybe-interesting values nearby, BIOS info etc.
static bool ReadProcessorString(std::string* value, const std::string& name)
{
  const DWORD flags = RRF_RT_REG_SZ | RRF_NOEXPAND;
  DWORD value_len = 0;
  auto status = RegGetValueA(HKEY_LOCAL_MACHINE, SUBKEY_CORE0, name.c_str(), flags, nullptr,
                             nullptr, &value_len);
  if (status != ERROR_SUCCESS && status != ERROR_MORE_DATA)
    return false;

  value->resize(value_len);
  status = RegGetValueA(HKEY_LOCAL_MACHINE, SUBKEY_CORE0, name.c_str(), flags, nullptr,
                        value->data(), &value_len);
  if (status != ERROR_SUCCESS)
  {
    value->clear();
    return false;
  }

  TruncateToCString(value);
  return true;
}

// Read cached register values from the registry
static bool ReadPrivilegedCPReg(u64* value, u32 reg)
{
  DWORD value_len = sizeof(*value);
  // Not sure if the value name is padded or not
  return RegGetValueA(HKEY_LOCAL_MACHINE, SUBKEY_CORE0, fmt::format("CP {:x}", reg).c_str(),
                      RRF_RT_REG_QWORD, nullptr, value, &value_len) == ERROR_SUCCESS;
}

static bool Read_MIDR_EL1(u64* value)
{
  return ReadPrivilegedCPReg(value, ARM64_SYSREG(0b11, 0, 0, 0b0000, 0));
}

static bool Read_ID_AA64ISAR0_EL1(u64* value)
{
  return ReadPrivilegedCPReg(value, ARM64_SYSREG(0b11, 0, 0, 0b0110, 0));
}

static bool Read_ID_AA64MMFR1_EL1(u64* value)
{
  return ReadPrivilegedCPReg(value, ARM64_SYSREG(0b11, 0, 0, 0b0111, 1));
}

#endif

#if defined(__linux__)

static bool ReadDeviceTree(std::string* value, const std::string& name)
{
  const std::string path = std::string("/proc/device-tree/") + name;
  std::ifstream file;
  File::OpenFStream(file, path.c_str(), std::ios_base::in);
  if (!file)
    return false;

  file >> *value;
  return true;
}

static std::string ReadCpuinfoField(const std::string& field)
{
  std::string line;
  std::ifstream file;
  File::OpenFStream(file, "/proc/cpuinfo", std::ios_base::in);
  if (!file)
    return {};

  while (std::getline(file, line))
  {
    if (!StringBeginsWith(line, field))
      continue;
    auto non_tab = line.find_first_not_of("\t", field.length());
    if (non_tab == line.npos)
      continue;
    if (line[non_tab] != ':')
      continue;
    auto value_start = line.find_first_not_of(" ", non_tab + 1);
    if (value_start == line.npos)
      continue;
    return line.substr(value_start);
  }
  return {};
}

static bool Read_MIDR_EL1_Sysfs(u64* value)
{
  std::ifstream file;
  File::OpenFStream(file, "/sys/devices/system/cpu/cpu0/regs/identification/midr_el1",
                    std::ios_base::in);
  if (!file)
    return false;

  file >> std::hex >> *value;
  return true;
}

#endif

#if defined(__linux__) || defined(__FreeBSD__)

static u32 ReadHwCap(u32 type)
{
#if defined(__linux__)
  return getauxval(type);
#elif defined(__FreeBSD__)
  u_long hwcap = 0;
  elf_aux_info(type, &hwcap, sizeof(hwcap));
  return hwcap;
#endif
}

// For "Direct" reads, value gets filled via emulation, hence:
// "there is no guarantee that the value reflects the processor that it is currently executing on"
// On big.LITTLE systems, the value may be unrelated to the core this is invoked on, and unless
// other measures are taken, executing the instruction may cause the caller to be switched onto a
// different core when it resumes (and of course, caller could be preempted at any other time as
// well).
static inline u64 Read_MIDR_EL1_Direct()
{
  u64 value;
  __asm__ __volatile__("mrs %0, MIDR_EL1" : "=r"(value));
  return value;
}

static bool Read_MIDR_EL1(u64* value)
{
#ifdef __linux__
  if (Read_MIDR_EL1_Sysfs(value))
    return true;
#endif

  bool id_reg_user_access = ReadHwCap(AT_HWCAP) & HWCAP_CPUID;
#ifdef __FreeBSD__
  // FreeBSD kernel has support but doesn't seem to indicate it?
  // see user_mrs_handler
  id_reg_user_access = true;
#endif
  if (!id_reg_user_access)
    return false;
  *value = Read_MIDR_EL1_Direct();
  return true;
}

#endif

#ifndef __APPLE__

static std::string MIDRToString(u64 midr)
{
  u8 implementer = (midr >> 24) & 0xff;
  u8 variant = (midr >> 20) & 0xf;
  u8 arch = (midr >> 16) & 0xf;
  u16 part_num = (midr >> 4) & 0xfff;
  u8 revision = midr & 0xf;
  return fmt::format("{:02X}:{:X}:{:04b}:{:03X}:{:X}", implementer, variant, arch, part_num,
                     revision);
}

#endif

CPUInfo cpu_info;

CPUInfo::CPUInfo()
{
  Detect();
}

void CPUInfo::Detect()
{
  vendor = CPUVendor::ARM;
  bFMA = true;
  bFlushToZero = true;

  num_cores = std::max(static_cast<int>(std::thread::hardware_concurrency()), 1);

#ifdef __APPLE__
  model_name = ReadSysctlByNameString("machdep.cpu.brand_string").value_or("(not found)");

  // M-series CPUs have all of these
  // Apparently the world has accepted that these can be assumed supported "for all time".
  // see https://github.com/golang/go/issues/42747
  bAES = true;
  bSHA1 = true;
  bSHA2 = true;
  bCRC32 = true;
#elif defined(_WIN32)
  // NOTE All this info is from cpu core 0 only.

  ReadProcessorString(&model_name, "ProcessorNameString");

  u64 reg = 0;
  // Attempt to be forward-compatible: perform inverted check against disabled feature states.
  if (Read_ID_AA64ISAR0_EL1(&reg))
  {
    bAES = ((reg >> 4) & 0xf) != 0;
    bSHA1 = ((reg >> 8) & 0xf) != 0;
    bSHA2 = ((reg >> 12) & 0xf) != 0;
    bCRC32 = ((reg >> 16) & 0xf) != 0;
  }
  if (Read_ID_AA64MMFR1_EL1(&reg))
  {
    // Introduced in Armv8.7, where AFP must be supported if AdvSIMD and FP both are.
    bAFP = ((reg >> 44) & 0xf) != 0;
  }
  // Pre-decoded MIDR_EL1 could be read with ReadProcessorString(.., "Identifier"),
  // but we want format to match across all platforms where possible.
  if (Read_MIDR_EL1(&reg))
  {
    cpu_id = MIDRToString(reg);
  }
#else
  // Linux, Android, and FreeBSD

#if defined(__FreeBSD__)
  model_name = ReadSysctlByNameString("hw.model").value_or("(not found)");
#elif defined(__linux__)
  if (!ReadDeviceTree(&model_name, "model"))
  {
    // This doesn't seem to work on modern arm64 kernels
    model_name = ReadCpuinfoField("Hardware");
  }
#endif

  const u32 hwcap = ReadHwCap(AT_HWCAP);
  bAES = hwcap & HWCAP_AES;
  bCRC32 = hwcap & HWCAP_CRC32;
  bSHA1 = hwcap & HWCAP_SHA1;
  bSHA2 = hwcap & HWCAP_SHA2;

#if defined(AT_HWCAP2) && defined(HWCAP2_AFP)
  const u32 hwcap2 = ReadHwCap(AT_HWCAP2);
  bAFP = hwcap2 & HWCAP2_AFP;
#endif

  u64 midr = 0;
  if (Read_MIDR_EL1(&midr))
  {
    cpu_id = MIDRToString(midr);
  }
#endif

  model_name = ReplaceAll(model_name, ",", "_");
  cpu_id = ReplaceAll(cpu_id, ",", "_");
}

std::string CPUInfo::Summarize()
{
  std::vector<std::string> sum;
  sum.push_back(model_name);
  sum.push_back(cpu_id);

  if (bAFP)
    sum.push_back("AFP");
  if (bAES)
    sum.push_back("AES");
  if (bCRC32)
    sum.push_back("CRC32");
  if (bSHA1)
    sum.push_back("SHA1");
  if (bSHA2)
    sum.push_back("SHA2");

  return JoinStrings(sum, ",");
}

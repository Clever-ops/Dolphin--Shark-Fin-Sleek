// Copyright 2008 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <array>
#include <memory>

#include "Common/BitField.h"
#include "Common/BitFieldView.h"
#include "Common/CommonTypes.h"

#include "Core/HW/GCMemcard/GCMemcard.h"

class PointerWrap;

namespace MMIO
{
class Mapping;
}

namespace ExpansionInterface
{
class IEXIDevice;
enum class EXIDeviceType : int;

class CEXIChannel
{
public:
  explicit CEXIChannel(u32 channel_id, const Memcard::HeaderData& memcard_header_data);
  ~CEXIChannel();

  // get device
  IEXIDevice* GetDevice(const u32 chip_select);

  void RegisterMMIO(MMIO::Mapping* mmio, u32 base);

  void SendTransferComplete();

  void AddDevice(EXIDeviceType device_type, int device_num);
  void AddDevice(std::unique_ptr<IEXIDevice> device, int device_num,
                 bool notify_presence_changed = true);

  // Remove all devices
  void RemoveDevices();

  bool IsCausingInterrupt();
  void DoState(PointerWrap& p);
  void PauseAndLock(bool do_lock, bool resume_on_unlock);

  // This should only be used to transition interrupts from SP1 to Channel 2
  void SetEXIINT(bool exiint);

private:
  enum
  {
    EXI_STATUS = 0x00,
    EXI_DMA_ADDRESS = 0x04,
    EXI_DMA_LENGTH = 0x08,
    EXI_DMA_CONTROL = 0x0C,
    EXI_IMM_DATA = 0x10
  };

  // EXI Status Register - "Channel Parameter Register"
  struct UEXI_STATUS
  {
    u32 Hex = 0;

    BFVIEW_M(Hex, bool, 0, 1, EXIINTMASK);
    BFVIEW_M(Hex, bool, 1, 1, EXIINT);
    BFVIEW_M(Hex, bool, 2, 1, TCINTMASK);
    BFVIEW_M(Hex, bool, 3, 1, TCINT);
    BFVIEW_M(Hex, u32, 4, 3, CLK);
    BFVIEW_M(Hex, bool, 7, 1, CS0);
    BFVIEW_M(Hex, bool, 8, 1, CS1);          // Channel 0 only
    BFVIEW_M(Hex, bool, 9, 1, CS2);          // Channel 0 only
    BFVIEW_M(Hex, bool, 10, 1, EXTINTMASK);  // Channel 0, 1 only
    BFVIEW_M(Hex, bool, 11, 1, EXTINT);      // Channel 0, 1 only
    BFVIEW_M(Hex, bool, 12, 1, EXT);         // Channel 0, 1 only
                                             // True means external EXI device present
    BFVIEW_M(Hex, bool, 13, 1, ROMDIS);      // Channel 0 only
                                             // ROM Disable
    BFVIEW_M(Hex, u32, 7, 3, CHIP_SELECT);   // CS0, CS1, and CS2 merged for convenience.

    UEXI_STATUS() = default;
    explicit UEXI_STATUS(u32 hex) : Hex{hex} {}
  };

  // EXI Control Register
  struct UEXI_CONTROL
  {
    u32 Hex = 0;

    BFVIEW_M(Hex, bool, 0, 1, TSTART);
    BFVIEW_M(Hex, bool, 1, 1, DMA);
    BFVIEW_M(Hex, u32, 2, 2, RW);
    BFVIEW_M(Hex, u32, 4, 2, TLEN);
  };

  // STATE_TO_SAVE
  UEXI_STATUS m_status;
  u32 m_dma_memory_address = 0;
  u32 m_dma_length = 0;
  UEXI_CONTROL m_control;
  u32 m_imm_data = 0;

  // Since channels operate a bit differently from each other
  u32 m_channel_id;

  // This data is needed in order to reinitialize a GCI folder memory card when switching between
  // GCI folder and other devices in the memory card slot or after loading a savestate. Even though
  // this data is only vaguely related to the EXI_Channel, this seems to be the best place to store
  // it, as this class creates the CEXIMemoryCard instances.
  Memcard::HeaderData m_memcard_header_data;

  // Devices
  enum
  {
    NUM_DEVICES = 3
  };

  std::array<std::unique_ptr<IEXIDevice>, NUM_DEVICES> m_devices;
};
}  // namespace ExpansionInterface

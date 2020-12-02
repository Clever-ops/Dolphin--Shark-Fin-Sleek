// Copyright 2008 Dolphin Emulator Project
// Licensed under GPLv2+
// Refer to the license.txt file included.

#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include "Common/ChunkFile.h"
#include "Common/CommonTypes.h"
#include "Common/Logging/Log.h"
#include "Core/IOS/IOS.h"

namespace IOS::HLE
{
enum ReturnCode : s32
{
  // Kernel return codes
  IPC_SUCCESS = 0,         // Success
  IPC_EACCES = -1,         // Permission denied
  IPC_EEXIST = -2,         // File exists
  IPC_EINTR = -3,          // Interrupted system call
  IPC_EINVAL = -4,         // Invalid argument or fd
  IPC_EMAX = -5,           // Too many file descriptors open
  IPC_ENOENT = -6,         // File not found
  IPC_EQUEUEEMPTY = -7,    // Queue empty
  IPC_EQUEUEFULL = -8,     // Queue full
  IPC_UNKNOWN = -9,        // Unknown error
  IPC_ENOTREADY = -10,     // Not ready
  IPC_ECC = -11,           // ECC error
  IPC_ECC_CRIT = -12,      // ECC critical error
  IPC_BADBLOCK = -13,         // Bad block
  IPC_INVALID_OBJTYPE = -14,  // Invalid object type
  IPC_INVALID_RNG = -15,      // Invalid RNG
  IPC_INVALID_FLAG = -16,  // Invalid flag
  IPC_INVALID_FORMAT = -17,   // Invalid format
  IPC_INVALID_VERSION = -18,  // Invalid version
  IPC_INVALID_SIGNER = -19,   // Invalid signer
  IPC_MISMATCH = -20,         // Value mismatch
  IPC_INTERNAL_ERROR = -21,   // IOS internal error
  IPC_ENOMEM = -22,        // Alloc failed during request
  IPC_INVALID_SIZE = -23,     // Invalid size
  IPC_ENOLINK = -24,          // No link
  // FS return codes
  FS_EINVAL = -101,        // Invalid path
  FS_EACCESS = -102,       // Permission denied
  FS_ECORRUPT = -103,      // Corrupted NAND
  FS_EEXIST = -105,        // File exists
  FS_ENOENT = -106,        // No such file or directory
  FS_ENFILE = -107,        // Too many fds open
  FS_EFBIG = -108,         // Max block count reached?
  FS_EFDEXHAUSTED = -109,  // Too many fds open
  FS_ENAMELEN = -110,      // Pathname is too long
  FS_EFDOPEN = -111,       // FD is already open
  FS_EIO = -114,           // ECC error
  FS_ENOTEMPTY = -115,     // Directory not empty
  FS_EDIRDEPTH = -116,     // Max directory depth exceeded
  FS_EBUSY = -118,         // Resource busy
  ES_SHORT_READ = -1009,   // Short read
  ES_EIO = -1010,          // Write failure
  ES_INVALID_SIGNATURE_TYPE = -1012,
  ES_FD_EXHAUSTED = -1016,  // Max of 3 ES handles exceeded
  ES_EINVAL = -1017,        // Invalid argument
  ES_DEVICE_ID_MISMATCH = -1020,
  ES_HASH_MISMATCH = -1022,  // Decrypted content hash doesn't match with the hash from the TMD
  ES_ENOMEM = -1024,         // Alloc failed during request
  ES_EACCES = -1026,         // Incorrect access rights (according to TMD)
  ES_UNKNOWN_ISSUER = -1027,
  ES_NO_TICKET = -1028,
  ES_INVALID_TICKET = -1029,
  IOSC_EACCES = -2000,
  IOSC_EEXIST = -2001,
  IOSC_EINVAL = -2002,
  IOSC_EMAX = -2003,
  IOSC_ENOENT = -2004,
  IOSC_INVALID_OBJTYPE = -2005,
  IOSC_INVALID_RNG = -2006,
  IOSC_INVALID_FLAG = -2007,
  IOSC_INVALID_FORMAT = -2008,
  IOSC_INVALID_VERSION = -2009,
  IOSC_INVALID_SIGNER = -2010,
  IOSC_FAIL_CHECKVALUE = -2011,
  IOSC_FAIL_INTERNAL = -2012,
  IOSC_FAIL_ALLOC = -2013,
  IOSC_INVALID_SIZE = -2014,
  IOSC_INVALID_ADDR = -2015,
  IOSC_INVALID_ALIGN = -2016,
  USB_ECANCELED = -7022,  // USB OH0 insertion hook cancelled
};

struct Request
{
  u32 address = 0;
  IPCCommandType command = IPC_CMD_OPEN;
  u32 fd = 0;
  explicit Request(u32 address);
  virtual ~Request() = default;
};

enum OpenMode : s32
{
  IOS_OPEN_NONE = 0,
  IOS_OPEN_READ = 1,
  IOS_OPEN_WRITE = 2,
  IOS_OPEN_RW = (IOS_OPEN_READ | IOS_OPEN_WRITE)
};

struct OpenRequest final : Request
{
  std::string path;
  OpenMode flags = IOS_OPEN_READ;
  // The UID and GID are not part of the IPC request sent from the PPC to the Starlet,
  // but they are set after they reach IOS and are dispatched to the appropriate module.
  u32 uid = 0;
  u16 gid = 0;
  explicit OpenRequest(u32 address);
};

struct ReadWriteRequest final : Request
{
  u32 buffer = 0;
  u32 size = 0;
  explicit ReadWriteRequest(u32 address);
};

enum SeekMode : s32
{
  IOS_SEEK_SET = 0,
  IOS_SEEK_CUR = 1,
  IOS_SEEK_END = 2,
};

struct SeekRequest final : Request
{
  u32 offset = 0;
  SeekMode mode = IOS_SEEK_SET;
  explicit SeekRequest(u32 address);
};

struct IOCtlRequest final : Request
{
  u32 request = 0;
  u32 buffer_in = 0;
  u32 buffer_in_size = 0;
  // Contrary to the name, the output buffer can also be used for input.
  u32 buffer_out = 0;
  u32 buffer_out_size = 0;
  explicit IOCtlRequest(u32 address);
  void Log(std::string_view description, Common::Log::LOG_TYPE type = Common::Log::IOS,
           Common::Log::LOG_LEVELS level = Common::Log::LINFO) const;
  void Dump(const std::string& description, Common::Log::LOG_TYPE type = Common::Log::IOS,
            Common::Log::LOG_LEVELS level = Common::Log::LINFO) const;
  void DumpUnknown(const std::string& description, Common::Log::LOG_TYPE type = Common::Log::IOS,
                   Common::Log::LOG_LEVELS level = Common::Log::LERROR) const;
};

struct IOCtlVRequest final : Request
{
  struct IOVector
  {
    u32 address = 0;
    u32 size = 0;
  };
  u32 request = 0;
  // In vectors are *mostly* used for input buffers. Sometimes they are also used as
  // output buffers (notably in the network code).
  // IO vectors are *mostly* used for output buffers. However, as indicated in the name,
  // they're also used as input buffers.
  // So both of them are technically IO vectors. But we're keeping them separated because
  // merging them into a single std::vector would make using the first out vector more complicated.
  std::vector<IOVector> in_vectors;
  std::vector<IOVector> io_vectors;

  /// Returns the specified vector or nullptr if the index is out of bounds.
  const IOVector* GetVector(size_t index) const;

  explicit IOCtlVRequest(u32 address);
  bool HasNumberOfValidVectors(size_t in_count, size_t io_count) const;
  void Dump(std::string_view description, Common::Log::LOG_TYPE type = Common::Log::IOS,
            Common::Log::LOG_LEVELS level = Common::Log::LINFO) const;
  void DumpUnknown(const std::string& description, Common::Log::LOG_TYPE type = Common::Log::IOS,
                   Common::Log::LOG_LEVELS level = Common::Log::LERROR) const;
};

class Device
{
public:
  enum class DeviceType : u32
  {
    Static,  // Devices which appear in s_device_map.
    OH0,     // OH0 child devices which are created dynamically.
  };

  Device(Kernel& ios, const std::string& device_name, DeviceType type = DeviceType::Static);

  virtual ~Device() = default;
  virtual void DoState(PointerWrap& p);
  void DoStateShared(PointerWrap& p);

  const std::string& GetDeviceName() const { return m_name; }
  // Replies to Open and Close requests are sent by the IPC request handler (HandleCommand),
  // not by the devices themselves.
  virtual std::optional<IPCReply> Open(const OpenRequest& request);
  virtual std::optional<IPCReply> Close(u32 fd);
  virtual std::optional<IPCReply> Seek(const SeekRequest& seek) { return Unsupported(seek); }
  virtual std::optional<IPCReply> Read(const ReadWriteRequest& read) { return Unsupported(read); }
  virtual std::optional<IPCReply> Write(const ReadWriteRequest& write)
  {
    return Unsupported(write);
  }
  virtual std::optional<IPCReply> IOCtl(const IOCtlRequest& ioctl) { return Unsupported(ioctl); }
  virtual std::optional<IPCReply> IOCtlV(const IOCtlVRequest& ioctlv)
  {
    return Unsupported(ioctlv);
  }
  virtual void Update() {}
  virtual void UpdateWantDeterminism(bool new_want_determinism) {}
  virtual DeviceType GetDeviceType() const { return m_device_type; }
  virtual bool IsOpened() const { return m_is_active; }

protected:
  Kernel& m_ios;

  std::string m_name;
  // STATE_TO_SAVE
  DeviceType m_device_type;
  bool m_is_active = false;

private:
  std::optional<IPCReply> Unsupported(const Request& request);
};
}  // namespace IOS::HLE

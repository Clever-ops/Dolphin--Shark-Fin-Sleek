// Copyright 2008 Dolphin Emulator Project
// Licensed under GPLv2+
// Refer to the license.txt file included.

#pragma once

#include <string>
#include <utility>

#include "Common/CommonTypes.h"

enum class APIType;
enum class TextureFormat;
enum class TLUTFormat;
enum TexelBufferFormat : u32;
struct EFBCopyParams;

namespace TextureConversionShaderTiled
{
std::string GenerateEncodingShader(const EFBCopyParams& params, APIType api_type);

// Information required to compile and dispatch a texture decoding shader.
struct DecodingShaderInfo
{
  TexelBufferFormat buffer_format;
  u32 palette_size;
  u32 group_size_x;
  u32 group_size_y;
  bool group_flatten;
  const char* shader_body;

  // Determine how many thread groups should be dispatched for an image of the specified
  // width/height.
  // First is the number of X groups, second is the number of Y groups, Z is always one.
  std::pair<u32, u32> GetDispatchCount(u32 width, u32 height) const;
};

// Obtain shader information for the specified texture format.
// If this format does not have a shader written for it, returns nullptr.
const DecodingShaderInfo* GetDecodingShaderInfo(TextureFormat format);

// Returns the string containing the texture decoding shader for the specified format.
std::string GenerateDecodingShader(TextureFormat format, TLUTFormat palette_format);

// Returns the string containing the palette conversion shader for the specified format.
std::string GeneratePaletteConversionShader(TLUTFormat palette_format, APIType api_type);

}  // namespace TextureConversionShaderTiled

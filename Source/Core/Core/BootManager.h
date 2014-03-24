// Copyright 2013 Dolphin Emulator Project
// Licensed under GPLv2
// Refer to the license.txt file included.

#pragma once

#include <string>

class GameListItem;

namespace BootManager
{
bool BootCore(const std::string& rFilename);

void Stop();
};

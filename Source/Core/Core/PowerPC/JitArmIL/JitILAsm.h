// Copyright 2014 Dolphin Emulator Project
// Licensed under GPLv2
// Refer to the license.txt file included.

#pragma once

#include "Common/ArmEmitter.h"
#include "Core/PowerPC/JitCommon/JitAsmCommon.h"

class JitArmILAsmRoutineManager : public CommonAsmRoutinesBase, public ArmGen::ARMCodeBlock
{
private:
	void Generate();
	void GenerateCommon() {}

public:
	void Init() {
		AllocCodeSpace(8192);
		Generate();
		WriteProtect();
	}

	void Shutdown() {
		FreeCodeSpace();
	}
};


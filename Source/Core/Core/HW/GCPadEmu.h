// Copyright 2010 Dolphin Emulator Project
// Licensed under GPLv2+
// Refer to the license.txt file included.

#pragma once

#include <string>

#include "InputCommon/ControllerEmu.h"

class GCPad : public ControllerEmu
{
public:

	GCPad(const unsigned int index);
	void GetInput(GCPadStatus* const pad);
	void SetOutput(const ControlState strength);
	void SetEmulatedInput(GCPadStatus const pad);

	bool GetMicButton() const;

	std::string GetName() const override;

	void LoadDefaults(const ControllerInterface& ciface) override;

private:
	
	bool           emu_set;
	GCPadStatus    emu_input;
	Buttons*       m_buttons;
	AnalogStick*   m_main_stick;
	AnalogStick*   m_c_stick;
	Buttons*       m_dpad;
	MixedTriggers* m_triggers;
	ControlGroup*  m_rumble;
	ControlGroup*  m_options;

	const unsigned int m_index;

	// TODO: Make constexpr when VS supports it.
	//
	// Default analog stick radius for GameCube controllers.
	static const ControlState DEFAULT_PAD_STICK_RADIUS;
};

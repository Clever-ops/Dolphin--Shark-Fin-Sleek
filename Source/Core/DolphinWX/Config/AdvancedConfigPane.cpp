// Copyright 2015 Dolphin Emulator Project
// Licensed under GPLv2+
// Refer to the license.txt file included.

#include <cmath>

#include <wx/checkbox.h>
#include <wx/sizer.h>
#include <wx/slider.h>
#include <wx/stattext.h>

#include "Core/ConfigManager.h"
#include "Core/Core.h"
#include "DolphinWX/Config/AdvancedConfigPane.h"

AdvancedConfigPane::AdvancedConfigPane(wxWindow* parent, wxWindowID id)
	: wxPanel(parent, id)
{
	InitializeGUI();
	LoadGUIValues();
	RefreshGUI();
}

void AdvancedConfigPane::InitializeGUI()
{
	m_clock_override_checkbox = new wxCheckBox(this, wxID_ANY, _("Enable CPU Clock Override"));
	m_clock_override_slider = new wxSlider(this, wxID_ANY, 100, 0, 150, wxDefaultPosition, wxSize(200,-1));
	m_clock_override_text = new wxStaticText(this, wxID_ANY, "");
	m_component_cable_checkbox = new wxCheckBox(this, wxID_ANY, _("Emulate Component Cable"));
	m_progressive_scan_checkbox = new wxCheckBox(this, wxID_ANY, _("Enable Progressive Scan"));

	m_clock_override_checkbox->Bind(wxEVT_CHECKBOX, &AdvancedConfigPane::OnClockOverrideCheckBoxChanged, this);
	m_clock_override_slider->Bind(wxEVT_SLIDER, &AdvancedConfigPane::OnClockOverrideSliderChanged, this);
	m_component_cable_checkbox->Bind(wxEVT_CHECKBOX, &AdvancedConfigPane::OnComponentCableCheckBoxChanged, this);
	m_progressive_scan_checkbox->Bind(wxEVT_CHECKBOX, &AdvancedConfigPane::OnProgressiveScanCheckBoxChanged, this);

	m_component_cable_checkbox->SetToolTip(_("Sets the type of video output hardware that is being emulated."));
	m_progressive_scan_checkbox->SetToolTip(_("Enables Progressive Scan if supported by the emulated software."));

	wxStaticText* const clock_override_description = new wxStaticText(this, wxID_ANY,
	  _("Higher values can make variable-framerate games "
	    "run at a higher framerate, at the expense of CPU. "
	    "Lower values can make variable-framerate games "
	    "run at a lower framerate, saving CPU.\n\n"
	    "WARNING: Changing this from the default (100%) "
	    "can and will break games and cause glitches. "
	    "Do so at your own risk. Please do not report "
	    "bugs that occur with a non-default clock. "));
	clock_override_description->Wrap(400);

	wxBoxSizer* const clock_override_checkbox_sizer = new wxBoxSizer(wxHORIZONTAL);
	clock_override_checkbox_sizer->Add(m_clock_override_checkbox, 1, wxALL, 5);

	wxBoxSizer* const clock_override_slider_sizer = new wxBoxSizer(wxHORIZONTAL);
	clock_override_slider_sizer->Add(m_clock_override_slider, 1, wxALL, 5);
	clock_override_slider_sizer->Add(m_clock_override_text, 1, wxALL, 5);

	wxBoxSizer* const clock_override_description_sizer = new wxBoxSizer(wxHORIZONTAL);
	clock_override_description_sizer->Add(clock_override_description, 1, wxALL, 5);

	wxStaticBoxSizer* const cpu_options_sizer = new wxStaticBoxSizer(wxVERTICAL, this, _("CPU Options"));
	cpu_options_sizer->Add(clock_override_checkbox_sizer);
	cpu_options_sizer->Add(clock_override_slider_sizer);
	cpu_options_sizer->Add(clock_override_description_sizer);

	wxStaticBoxSizer* const misc_settings_static_sizer = new wxStaticBoxSizer(wxVERTICAL, this, _("Output"));
	misc_settings_static_sizer->Add(m_component_cable_checkbox, 0, wxALL, 5);
	misc_settings_static_sizer->Add(m_progressive_scan_checkbox, 0, wxALL, 5);

	wxBoxSizer* const main_sizer = new wxBoxSizer(wxVERTICAL);
	main_sizer->Add(cpu_options_sizer , 0, wxEXPAND | wxALL, 5);
	main_sizer->Add(misc_settings_static_sizer, 0, wxEXPAND | wxALL, 5);

	SetSizer(main_sizer);
}

void AdvancedConfigPane::LoadGUIValues()
{
	int ocFactor = (int)(std::log2f(SConfig::GetInstance().m_OCFactor) * 25.f + 100.f + 0.5f);
	bool oc_enabled = SConfig::GetInstance().m_OCEnable;
	m_clock_override_checkbox->SetValue(oc_enabled);
	m_clock_override_slider ->SetValue(ocFactor);
	m_clock_override_slider->Enable(oc_enabled);
	UpdateCPUClock();
	m_component_cable_checkbox->SetValue(SConfig::GetInstance().bComponentCable);
	m_progressive_scan_checkbox->SetValue(SConfig::GetInstance().bProgressive);
}

void AdvancedConfigPane::RefreshGUI()
{
	// Progressive Scan only works with a Component Cable
	m_progressive_scan_checkbox->Enable(m_component_cable_checkbox->IsChecked());

	if (Core::IsRunning())
	{
		m_component_cable_checkbox->Disable();
		m_progressive_scan_checkbox->Disable();
	}
}

void AdvancedConfigPane::OnClockOverrideCheckBoxChanged(wxCommandEvent& event)
{
	SConfig::GetInstance().m_OCEnable = m_clock_override_checkbox->IsChecked();
	m_clock_override_slider->Enable(SConfig::GetInstance().m_OCEnable);
	UpdateCPUClock();
}

void AdvancedConfigPane::OnClockOverrideSliderChanged(wxCommandEvent& event)
{
	// Vaguely exponential scaling?
	SConfig::GetInstance().m_OCFactor = std::exp2f((m_clock_override_slider->GetValue() - 100.f) / 25.f);
	UpdateCPUClock();
}

void AdvancedConfigPane::UpdateCPUClock()
{
	bool wii = SConfig::GetInstance().bWii;
	int percent = (int)(std::roundf(SConfig::GetInstance().m_OCFactor * 100.f));
	int clock = (int)(std::roundf(SConfig::GetInstance().m_OCFactor * (wii ? 729.f : 486.f)));

	m_clock_override_text->SetLabel(SConfig::GetInstance().m_OCEnable ? wxString::Format("%d %% (%d mhz)", percent, clock) : "");
}

void AdvancedConfigPane::OnComponentCableCheckBoxChanged(wxCommandEvent& event)
{
	const bool bComponentCable = m_component_cable_checkbox->IsChecked();
	SConfig::GetInstance().bComponentCable = bComponentCable;
	if (!bComponentCable)
	{
		SConfig::GetInstance().bProgressive = false;
		m_progressive_scan_checkbox->SetValue(false);
	}
	RefreshGUI();
}

void AdvancedConfigPane::OnProgressiveScanCheckBoxChanged(wxCommandEvent& event)
{
	const bool bProgressive = m_progressive_scan_checkbox->IsChecked();
	SConfig::GetInstance().bProgressive = bProgressive;
	SConfig::GetInstance().m_SYSCONF->SetData("IPL.PGS", bProgressive);
}

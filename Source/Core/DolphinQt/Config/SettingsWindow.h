// Copyright 2015 Dolphin Emulator Project
// Licensed under GPLv2+
// Refer to the license.txt file included.

#pragma once

#include "DolphinQt/QtUtils/CustomDialog.h"

class QTabWidget;

enum class TabIndex
{
  General = 0,
  Audio = 2
};

class SettingsWindow final : public CustomDialog
{
  Q_OBJECT
public:
  explicit SettingsWindow(QWidget* parent = nullptr);
  void SelectGeneralPane();
  void SelectAudioPane();

private:
  QTabWidget* m_tab_widget;
};

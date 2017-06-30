// Copyright 2017 Dolphin Emulator Project
// Licensed under GPLv2+
// Refer to the license.txt file included.

#include "DolphinQt2/Config/Graphics/GraphicsBool.h"
#include <wobjectimpl.h>

#include "Core/Config/Config.h"

#include <QFont>

W_OBJECT_IMPL(GraphicsBool)

GraphicsBool::GraphicsBool(const QString& label, const Config::ConfigInfo<bool>& setting,
                           bool reverse)
    : QCheckBox(label), m_setting(setting), m_reverse(reverse)
{
  connect(this, &QCheckBox::toggled, this, &GraphicsBool::Update);
  setChecked(Config::Get(m_setting) ^ reverse);

  if (Config::GetActiveLayerForConfig(m_setting) != Config::LayerType::Base)
  {
    QFont bf = font();
    bf.setBold(true);
    setFont(bf);
  }
}

void GraphicsBool::Update()
{
  Config::SetBaseOrCurrent(m_setting, static_cast<bool>(isChecked() ^ m_reverse));
}

W_OBJECT_IMPL(GraphicsBoolEx)

GraphicsBoolEx::GraphicsBoolEx(const QString& label, const Config::ConfigInfo<bool>& setting,
                               bool reverse)
    : QRadioButton(label), m_setting(setting), m_reverse(reverse)
{
  connect(this, &QCheckBox::toggled, this, &GraphicsBoolEx::Update);
  setChecked(Config::Get(m_setting) ^ reverse);

  if (Config::GetActiveLayerForConfig(m_setting) != Config::LayerType::Base)
  {
    QFont bf = font();
    bf.setBold(true);
    setFont(bf);
  }
}

void GraphicsBoolEx::Update()
{
  Config::SetBaseOrCurrent(m_setting, static_cast<bool>(isChecked() ^ m_reverse));
}

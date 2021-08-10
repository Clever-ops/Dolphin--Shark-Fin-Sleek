// SPDX-License-Identifier: GPL-2.0-or-later

package org.dolphinemu.dolphinemu.features.cheats.ui;

import android.view.View;
import android.widget.TextView;

import androidx.annotation.NonNull;

import org.dolphinemu.dolphinemu.R;
import org.dolphinemu.dolphinemu.features.cheats.model.ARCheat;
import org.dolphinemu.dolphinemu.features.cheats.model.CheatsViewModel;
import org.dolphinemu.dolphinemu.features.cheats.model.GeckoCheat;
import org.dolphinemu.dolphinemu.features.cheats.model.PatchCheat;

public class ActionViewHolder extends CheatItemViewHolder implements View.OnClickListener
{
  private final TextView mName;

  private CheatsViewModel mViewModel;
  private int mString;
  private int mPosition;

  public ActionViewHolder(@NonNull View itemView)
  {
    super(itemView);

    mName = itemView.findViewById(R.id.text_setting_name);

    itemView.setOnClickListener(this);
  }

  public void bind(CheatsViewModel viewModel, CheatItem item, int position)
  {
    mViewModel = viewModel;
    mString = item.getString();
    mPosition = position;

    mName.setText(mString);
  }

  public void onClick(View root)
  {
    if (mString == R.string.cheats_add_ar)
    {
      mViewModel.startAddingCheat(new ARCheat(), mPosition);
      mViewModel.openDetailsView();
    }
    else if (mString == R.string.cheats_add_gecko)
    {
      mViewModel.startAddingCheat(new GeckoCheat(), mPosition);
      mViewModel.openDetailsView();
    }
    else if (mString == R.string.cheats_add_patch)
    {
      mViewModel.startAddingCheat(new PatchCheat(), mPosition);
      mViewModel.openDetailsView();
    }
  }
}

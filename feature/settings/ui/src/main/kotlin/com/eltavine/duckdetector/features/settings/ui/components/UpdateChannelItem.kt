/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.eltavine.duckdetector.features.settings.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Layers
import androidx.compose.material3.ListItemShapes
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.features.settings.presentation.model.SettingsUpdateChannel
import com.eltavine.duckdetector.features.settings.ui.R

/** The channel the update check follows; picking the other one checks it at once. */
@Composable
internal fun UpdateChannelItem(
    channel: SettingsUpdateChannel,
    shapes: ListItemShapes,
    onChannelChange: (SettingsUpdateChannel) -> Unit,
) {
    SettingsItem(
        headline = stringResource(R.string.update_channel_label),
        shapes = shapes,
        leadingContent = { SettingsIconTile(icon = Icons.Rounded.Layers) },
        supportingContent = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                WrapSafeText(text = stringResource(channel.summary()))
                SingleChoiceSegmentedButtonRow(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 2.dp),
                ) {
                    val options = SettingsUpdateChannel.entries
                    options.forEachIndexed { index, option ->
                        SegmentedButton(
                            selected = option == channel,
                            onClick = { onChannelChange(option) },
                            shape = SegmentedButtonDefaults.itemShape(index = index, count = options.size),
                            label = { WrapSafeText(text = stringResource(option.label())) },
                        )
                    }
                }
            }
        },
    )
}

internal fun SettingsUpdateChannel.label(): Int = when (this) {
    SettingsUpdateChannel.STABLE -> R.string.update_channel_stable
    SettingsUpdateChannel.NIGHTLY -> R.string.update_channel_nightly
}

private fun SettingsUpdateChannel.summary(): Int = when (this) {
    SettingsUpdateChannel.STABLE -> R.string.update_channel_stable_summary
    SettingsUpdateChannel.NIGHTLY -> R.string.update_channel_nightly_summary
}

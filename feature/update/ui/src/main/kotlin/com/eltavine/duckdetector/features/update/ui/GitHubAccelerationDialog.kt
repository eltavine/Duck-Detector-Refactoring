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

package com.eltavine.duckdetector.features.update.ui

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.eltavine.duckdetector.core.designsystem.theme.ShapeTokens
import io.github.xiaotong6666.uihelper.dialog.AdaptiveDecisionDialog

/** [onDecline] is the user's answer; [onDismiss] only closes the dialog and leaves the choice open. */
@Composable
fun GitHubAccelerationDialog(
    onEnable: () -> Unit,
    onDecline: () -> Unit,
    onDismiss: () -> Unit,
) {
    AdaptiveDecisionDialog(
        show = true,
        title = stringResource(R.string.github_acceleration_dialog_title),
        message = stringResource(R.string.github_acceleration_dialog_message),
        confirmLabel = stringResource(R.string.github_acceleration_dialog_enable),
        dismissLabel = stringResource(R.string.github_acceleration_dialog_decline),
        onConfirm = onEnable,
        onDismissButton = onDecline,
        onDismissRequest = onDismiss,
        icon = Icons.Rounded.Speed,
        materialShape = ShapeTokens.CornerExtraLarge,
        materialContainerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
    )
}

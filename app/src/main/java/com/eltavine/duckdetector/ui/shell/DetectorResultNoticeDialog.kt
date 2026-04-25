/*
 * Copyright 2026 Duck Apps Contributor
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

package com.eltavine.duckdetector.ui.shell

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.R
import com.eltavine.duckdetector.core.ui.model.DetectionSeverity
import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.features.dashboard.ui.model.DashboardDetectorContribution
import kotlinx.coroutines.delay

internal const val RESULT_NOTICE_LOCK_SECONDS = 5

internal fun shouldShowDetectorResultNotice(
    isLoading: Boolean,
    overviewStatus: DetectorStatus,
): Boolean {
    return !isLoading && when (overviewStatus.severity) {
        DetectionSeverity.DANGER,
        DetectionSeverity.WARNING -> true

        DetectionSeverity.INFO,
        DetectionSeverity.ALL_CLEAR -> false
    }
}

internal fun attentionDetectorTitles(
    contributions: List<DashboardDetectorContribution>,
): Set<String> {
    return contributions
        .filter { contribution ->
            contribution.ready && when (contribution.status.severity) {
                DetectionSeverity.DANGER,
                DetectionSeverity.WARNING -> true

                DetectionSeverity.INFO,
                DetectionSeverity.ALL_CLEAR -> false
            }
        }
        .mapTo(linkedSetOf()) { contribution -> contribution.title }
}

@Composable
fun DetectorResultNoticeDialog(
    onDismiss: () -> Unit,
) {
    var secondsRemaining by rememberSaveable { mutableIntStateOf(RESULT_NOTICE_LOCK_SECONDS) }
    val canDismiss = secondsRemaining == 0

    LaunchedEffect(Unit) {
        while (secondsRemaining > 0) {
            delay(1_000)
            secondsRemaining -= 1
        }
    }

    AlertDialog(
        onDismissRequest = {
            if (canDismiss) {
                onDismiss()
            }
        },
        properties = DialogProperties(
            dismissOnBackPress = canDismiss,
            dismissOnClickOutside = canDismiss,
        ),
        title = {
            WrapSafeText(
                text = stringResource(R.string.detector_result_title),
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
        },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                WrapSafeText(
                    text = stringResource(R.string.detector_result_notice),
                    modifier = Modifier.fillMaxWidth(),
                    style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                    color = MaterialTheme.colorScheme.error,
                    textAlign = TextAlign.Center,
                )
                WrapSafeText(
                    text = stringResource(R.string.detector_result_detail),
                    modifier = Modifier.fillMaxWidth(),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = onDismiss,
                enabled = canDismiss,
            ) {
                WrapSafeText(
                    text = if (canDismiss) {
                        stringResource(R.string.dialog_continue)
                    } else {
                        stringResource(R.string.dialog_continue_waiting, secondsRemaining)
                    },
                    style = MaterialTheme.typography.labelLarge,
                )
            }
        },
    )
}

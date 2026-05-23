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

package com.eltavine.duckdetector.features.crashreport.ui

import android.content.ClipData
import android.content.Intent
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.BugReport
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.FileDownload
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.features.crashreport.data.CrashHandler
import com.eltavine.duckdetector.features.crashreport.data.CrashReportFormatter
import com.eltavine.duckdetector.features.crashreport.domain.CrashReport
import com.eltavine.duckdetector.ui.theme.ShapeTokens
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * A banner displayed when a crash was detected from a previous session.
 * Offers actions: copy text, save TXT, dismiss.
 */
@Composable
fun CrashReportBanner(
    report: CrashReport,
    isStartupCrash: Boolean = false,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    var dismissed by remember { mutableStateOf(false) }

    val txtLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("text/plain"),
    ) { uri ->
        if (uri != null) {
            runCatching {
                val text = CrashReportFormatter.format(report)
                context.contentResolver.openOutputStream(uri)?.use { stream ->
                    stream.write(text.toByteArray(Charsets.UTF_8))
                }
                Toast.makeText(context, "Crash report saved", Toast.LENGTH_SHORT).show()
            }.getOrElse { e ->
                Toast.makeText(context, "Save failed: ${e.message}", Toast.LENGTH_SHORT).show()
            }
        }
    }

    if (dismissed) return

    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = ShapeTokens.CornerExtraLargeIncreased,
        color = MaterialTheme.colorScheme.errorContainer,
    ) {
        Column(
            modifier = Modifier.padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            // Header row
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Icon(
                        imageVector = Icons.Rounded.BugReport,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onErrorContainer,
                        modifier = Modifier.size(22.dp),
                    )
                    WrapSafeText(
                        text = if (isStartupCrash) "App Failed to Start" else "Previous Crash Detected",
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                    )
                }
                IconButton(
                    onClick = {
                        dismissed = true
                        onDismiss()
                    },
                    modifier = Modifier.size(32.dp),
                ) {
                    Icon(
                        imageVector = Icons.Rounded.Close,
                        contentDescription = "Dismiss",
                        tint = MaterialTheme.colorScheme.onErrorContainer,
                        modifier = Modifier.size(18.dp),
                    )
                }
            }

            // Crash summary
            WrapSafeText(
                text = buildSummary(report, isStartupCrash),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onErrorContainer,
            )

            HorizontalDivider(
                color = MaterialTheme.colorScheme.onErrorContainer.copy(alpha = 0.2f),
                thickness = 1.dp,
            )

            // Action buttons
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedButton(
                    onClick = {
                        val text = CrashReportFormatter.format(report)
                        val clipboard = context.getSystemService(android.content.ClipboardManager::class.java)
                        clipboard?.setPrimaryClip(
                            ClipData.newPlainText("Crash Report", text),
                        )
                        Toast.makeText(context, "Crash report copied", Toast.LENGTH_SHORT).show()
                    },
                    modifier = Modifier.weight(1f),
                ) {
                    Icon(
                        imageVector = Icons.Rounded.ContentCopy,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp),
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    WrapSafeText(
                        text = "Copy",
                        style = MaterialTheme.typography.labelMedium,
                    )
                }

                OutlinedButton(
                    onClick = {
                        txtLauncher.launch("duck_crash_report.txt")
                    },
                    modifier = Modifier.weight(1f),
                ) {
                    Icon(
                        imageVector = Icons.Rounded.FileDownload,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp),
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    WrapSafeText(
                        text = "Save TXT",
                        style = MaterialTheme.typography.labelMedium,
                    )
                }

                TextButton(
                    onClick = {
                        CrashHandler.clearAll(context)
                        dismissed = true
                        onDismiss()
                        Toast.makeText(context, "Crash reports cleared", Toast.LENGTH_SHORT).show()
                    },
                ) {
                    Icon(
                        imageVector = Icons.Rounded.Delete,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp),
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    WrapSafeText(
                        text = "Clear",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                    )
                }
            }
        }
    }
}

private fun buildSummary(report: CrashReport, isStartupCrash: Boolean): String {
    val time = SimpleDateFormat("MM-dd HH:mm", Locale.US).format(Date(report.crashTimeUtcMillis))
    val exception = report.exceptionClassName.substringAfterLast('.')
    val model = report.deviceSections
        .firstOrNull { it.title == "Identity" }
        ?.entries?.firstOrNull { it.label == "Model" }?.value ?: "Unknown"
    val release = report.deviceSections
        .firstOrNull { it.title == "Android" }
        ?.entries?.firstOrNull { it.label == "Release" }?.value ?: "Unknown"

    val prefix = if (isStartupCrash) {
        "⚠ The app crashed during startup and could not open.\n"
    } else {
        ""
    }

    return "${prefix}App v${report.appVersionName} crashed on $model (Android $release) at $time.\n" +
        "Exception: $exception — ${report.exceptionMessage.take(120)}"
}

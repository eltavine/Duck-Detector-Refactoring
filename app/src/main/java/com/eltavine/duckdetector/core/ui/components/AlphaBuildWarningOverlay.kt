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

package com.eltavine.duckdetector.core.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.Image
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.OpenInNew
import androidx.compose.material.icons.rounded.BugReport
import androidx.compose.material.icons.rounded.Download
import androidx.compose.material.icons.rounded.Schedule
import androidx.compose.material.icons.rounded.WarningAmber
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.eltavine.duckdetector.BuildConfig
import com.eltavine.duckdetector.R
import kotlinx.coroutines.delay

private const val APP_ERRORS_TRACKING_GITHUB =
    "https://github.com/KitsunePie/AppErrorsTracking/actions"
private const val APP_ERRORS_TRACKING_TELEGRAM =
    "https://t.me/AppErrorsTracking_CI"

@Composable
fun AlphaBuildWarningOverlay(
    versionName: String = BuildConfig.VERSION_NAME,
    isAlphaBuild: Boolean = BuildConfig.isAlphaVersion,
    forceVisible: Boolean? = null,
    onDismissed: (() -> Unit)? = null,
) {
    val shouldShow = isAlphaBuild
    var internalVisible by rememberSaveable(versionName, isAlphaBuild) { mutableStateOf(shouldShow) }
    var remainingSeconds by rememberSaveable(versionName, isAlphaBuild) {
        mutableIntStateOf(if (shouldShow) 3 else 0)
    }
    val visible = forceVisible ?: internalVisible

    LaunchedEffect(visible, shouldShow) {
        if (!visible || !shouldShow) {
            return@LaunchedEffect
        }
        remainingSeconds = 3
        while (remainingSeconds > 0) {
            delay(1_000L)
            remainingSeconds -= 1
        }
    }

    if (!visible || !shouldShow) {
        return
    }

    val canDismiss = remainingSeconds == 0
    val uriHandler = LocalUriHandler.current
    val scrollState = rememberScrollState()
    val dismissOverlay = {
        if (forceVisible == null) {
            internalVisible = false
        }
        onDismissed?.invoke()
    }

    Dialog(
        onDismissRequest = {
            if (canDismiss) {
                dismissOverlay()
            }
        },
        properties = DialogProperties(
            dismissOnBackPress = canDismiss,
            dismissOnClickOutside = canDismiss,
            usePlatformDefaultWidth = false,
        ),
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(20.dp),
            contentAlignment = Alignment.Center,
        ) {
            Surface(
                modifier = Modifier.widthIn(max = 560.dp),
                shape = RoundedCornerShape(28.dp),
                color = MaterialTheme.colorScheme.surface,
                tonalElevation = 10.dp,
                shadowElevation = 18.dp,
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .verticalScroll(scrollState)
                        .padding(horizontal = 22.dp, vertical = 20.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp),
                ) {
                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        Text(
                            text = stringResource(R.string.alpha_title),
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Black,
                            color = MaterialTheme.colorScheme.error,
                        )
                        Text(
                            text = "v$versionName",
                            style = MaterialTheme.typography.labelLarge,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            fontFamily = FontFamily.Monospace,
                        )
                    }

                    Text(
                        text = stringResource(R.string.alpha_message),
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurface,
                    )

                    AlphaInfoRow(
                        icon = Icons.Rounded.WarningAmber,
                        iconTint = MaterialTheme.colorScheme.error,
                        text = stringResource(R.string.alpha_warning_runtime),
                    )
                    AlphaInfoRow(
                        icon = Icons.Rounded.BugReport,
                        iconTint = MaterialTheme.colorScheme.tertiary,
                        text = stringResource(R.string.alpha_warning_report),
                    )
                    AlphaInfoRow(
                        icon = Icons.Rounded.Download,
                        iconTint = MaterialTheme.colorScheme.primary,
                        text = stringResource(R.string.alpha_warning_download),
                    )

                    Text(
                        text = stringResource(R.string.alpha_helper),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(18.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        ExternalLinkIcon(
                            iconResId = R.drawable.ic_github,
                            label = stringResource(R.string.social_github),
                            onOpen = { uriHandler.openUri(APP_ERRORS_TRACKING_GITHUB) },
                        )
                        ExternalLinkIcon(
                            iconResId = R.drawable.ic_telegram,
                            label = stringResource(R.string.social_telegram),
                            onOpen = { uriHandler.openUri(APP_ERRORS_TRACKING_TELEGRAM) },
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Schedule,
                            contentDescription = null,
                            tint = if (canDismiss) {
                                MaterialTheme.colorScheme.primary
                            } else {
                                MaterialTheme.colorScheme.onSurfaceVariant
                            },
                            modifier = Modifier.size(18.dp),
                        )
                        Text(
                            text = if (canDismiss) {
                                stringResource(R.string.alpha_dismiss_ready)
                            } else {
                                stringResource(R.string.alpha_dismiss_waiting, remainingSeconds)
                            },
                            style = MaterialTheme.typography.labelLarge,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }

                    Button(
                        onClick = {
                            if (canDismiss) {
                                dismissOverlay()
                            }
                        },
                        enabled = canDismiss,
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.error,
                        ),
                    ) {
                        Text(
                            text = if (canDismiss) {
                                stringResource(R.string.alpha_continue)
                            } else {
                                stringResource(R.string.alpha_continue_waiting, remainingSeconds)
                            },
                            fontWeight = FontWeight.Bold,
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun AlphaBuildBanner(
    modifier: Modifier = Modifier,
    isAlphaBuild: Boolean = BuildConfig.isAlphaVersion,
) {
    if (!isAlphaBuild) {
        return
    }

    val isDarkTheme = isSystemInDarkTheme()
    val bannerColor = if (isDarkTheme) Color(0xFFFFB74D) else Color(0xFFD84315)
    val textColor = if (isDarkTheme) Color.Black else Color.White

    Box(
        modifier = modifier.fillMaxSize(),
    ) {
        Box(
            modifier = Modifier
                .align(Alignment.TopEnd)
                .offset(x = 32.dp, y = 28.dp)
                .rotate(45f)
                .background(bannerColor)
                .width(140.dp)
                .heightIn(min = 24.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = stringResource(R.string.alpha_banner),
                color = textColor,
                fontSize = 10.sp,
                fontWeight = FontWeight.Bold,
                textAlign = TextAlign.Center,
            )
        }
    }
}

@Composable
private fun AlphaInfoRow(
    icon: ImageVector,
    iconTint: Color,
    text: String,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Box(
            modifier = Modifier
                .padding(top = 2.dp)
                .size(30.dp)
                .background(iconTint.copy(alpha = 0.14f), CircleShape),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = iconTint,
                modifier = Modifier.size(18.dp),
            )
        }
        Text(
            text = text,
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

@Composable
private fun ExternalLinkIcon(
    iconResId: Int,
    label: String,
    onOpen: () -> Unit,
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Surface(
            modifier = Modifier
                .size(54.dp)
                .clip(CircleShape),
            shape = CircleShape,
            color = MaterialTheme.colorScheme.surfaceContainerHigh,
            onClick = onOpen,
        ) {
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.Center,
            ) {
                Image(
                    painter = painterResource(id = iconResId),
                    contentDescription = null,
                    modifier = Modifier.size(24.dp),
                )
            }
        }
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = label,
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.primary,
            )
            Icon(
                imageVector = Icons.AutoMirrored.Rounded.OpenInNew,
                contentDescription = null,
                modifier = Modifier.size(14.dp),
                tint = MaterialTheme.colorScheme.primary,
            )
        }
    }
}

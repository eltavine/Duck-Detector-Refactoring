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

package com.eltavine.duckdetector.features.dashboard.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.RoundRect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathMeasure
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.clipPath
import androidx.compose.ui.graphics.drawscope.withTransform
import androidx.compose.ui.graphics.vector.PathParser
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.draw.drawWithCache
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.ui.components.DuckIcon
import io.github.xiaotong6666.uihelper.adaptive.adaptiveOnSurfaceColor
import com.eltavine.duckdetector.features.dashboard.presentation.model.HistoricalVerdict
import com.eltavine.duckdetector.features.dashboard.presentation.model.HistorySegment
import com.eltavine.duckdetector.features.dashboard.presentation.model.ScanHistoryCounts

/** The Material tile keeps its original geometry; only its existing edge gains history colors. */
@Composable
internal fun Modifier.materialScanHistoryBorder(counts: ScanHistoryCounts): Modifier {
    val palette = DuckTheme.palette
    val sections = counts.segments()
    val danger = historyAccent(palette.critical, palette.neutral)
    val warning = historyAccent(palette.caution, palette.neutral)
    val clear = historyAccent(palette.positive, palette.neutral)
    val empty = palette.neutral.copy(alpha = EMPTY_HISTORY_ALPHA)
    return this.drawWithCache {
        val inset = 1.dp.toPx()
        val roundRect = Path().apply {
            addRoundRect(
                RoundRect(
                    left = inset,
                    top = inset,
                    right = size.width - inset,
                    bottom = size.height - inset,
                    cornerRadius = CornerRadius((size.minDimension / 4f - inset).coerceAtLeast(0f)),
                ),
            )
        }
        onDrawWithContent {
            drawContent()
            drawHistorySections(
                roundRect,
                sections,
                strokeWidth = 1.dp.toPx(),
                gapWidth = 1.dp.toPx(),
                emptyColor = empty,
                colorFor = { verdict ->
                    when (verdict) {
                        HistoricalVerdict.DANGER -> danger
                        HistoricalVerdict.WARNING -> warning
                        HistoricalVerdict.CLEAR -> clear
                        HistoricalVerdict.INCONCLUSIVE -> empty
                    }
                },
            )
        }
    }
}

/** Keep the outline unchanged and color the existing wing stroke by history proportions. */
@Composable
internal fun MiuixHistoryDuck(counts: ScanHistoryCounts, modifier: Modifier = Modifier) {
    val palette = DuckTheme.palette
    val contentColor = adaptiveOnSurfaceColor()
    val sections = counts.segments()
    val wing = remember { PathParser().parsePathString(DUCK_WING).toPath() }
    val wingCenter = remember {
        Path().apply {
            moveTo(149f, 211f)
            cubicTo(195f, 211f, 232f, 233f, 226f, 265f)
            cubicTo(222f, 296f, 191f, 311f, 146f, 307f)
        }
    }
    Box(modifier = modifier) {
        DuckIcon(
            painter = painterResource(R.drawable.ic_duck_logo),
            contentDescription = null,
            tint = contentColor,
            modifier = Modifier.fillMaxSize(),
        )
        val danger = historyAccent(palette.critical, palette.neutral)
        val warning = historyAccent(palette.caution, palette.neutral)
        val clear = historyAccent(palette.positive, palette.neutral)
        val empty = palette.neutral.copy(alpha = EMPTY_HISTORY_ALPHA)
        Canvas(modifier = Modifier.fillMaxSize()) {
            withTransform({
                scale(size.width / DUCK_VIEWPORT, size.height / DUCK_VIEWPORT, pivot = Offset.Zero)
            }) {
                clipPath(wing) {
                    drawHistorySections(
                        wingCenter,
                        sections,
                        strokeWidth = 48f,
                        gapWidth = 5f,
                        emptyColor = empty,
                        forceClosed = false,
                        colorFor = { verdict ->
                            when (verdict) {
                                HistoricalVerdict.DANGER -> danger
                                HistoricalVerdict.WARNING -> warning
                                HistoricalVerdict.CLEAR -> clear
                                HistoricalVerdict.INCONCLUSIVE -> empty
                            }
                        },
                    )
                }
            }
        }
    }
}

// History is a quiet accent, not another danger banner. Keep hue distinctions at icon size.
private fun historyAccent(color: Color, neutral: Color): Color =
    lerp(neutral, color, HISTORY_COLOR_FRACTION).copy(alpha = HISTORY_ALPHA)

private const val HISTORY_COLOR_FRACTION = 0.65f
private const val HISTORY_ALPHA = 0.72f
private const val EMPTY_HISTORY_ALPHA = 0.50f

private fun DrawScope.drawHistorySections(
    path: Path,
    sections: List<HistorySegment>,
    strokeWidth: Float,
    gapWidth: Float,
    emptyColor: Color,
    forceClosed: Boolean = true,
    colorFor: (HistoricalVerdict) -> Color,
) {
    val measure = PathMeasure().apply { setPath(path, forceClosed = forceClosed) }
    val length = measure.length
    if (length <= 0f) return
    if (sections.isEmpty()) {
        drawPath(path, emptyColor, style = Stroke(width = strokeWidth, cap = StrokeCap.Round))
        return
    }
    var start = 0f
    sections.forEachIndexed { index, section ->
        val end = if (index == sections.lastIndex) length else
            (start + length * section.fraction).coerceAtMost(length)
        val begin = start + if (sections.size == 1) 0f else gapWidth / 2f
        val finish = end - if (sections.size == 1) 0f else gapWidth / 2f
        if (finish > begin) {
            val part = Path()
            measure.getSegment(begin, finish, part, startWithMoveTo = true)
            drawPath(part, colorFor(section.verdict), style = Stroke(width = strokeWidth, cap = StrokeCap.Butt))
        }
        start = end
    }
}

private const val DUCK_VIEWPORT = 359.61f
// Exact filled wing shape from ic_duck_logo.xml, used only as a clipping mask.
private const val DUCK_WING = """M215.51,222.49c-13.38,-11.35 -31.62,-18.44 -51.37,-19.96c-5.19,-0.33 -9.65,3.45 -10.05,8.6c-0.4,5.15 3.46,9.65 8.61,10.05c15.86,1.23 30.32,6.75 40.72,15.58c9.53,8.09 14.37,17.94 13.61,27.75c-0.76,9.8 -7.05,18.8 -17.71,25.33c-11.63,7.12 -26.76,10.36 -42.63,9.13c-5.18,-0.35 -9.65,3.46 -10.04,8.6c-0.4,5.15 3.46,9.65 8.6,10.05c2.66,0.21 5.31,0.31 7.93,0.31c16.89,0 32.95,-4.21 45.91,-12.13c15.92,-9.74 25.37,-23.89 26.6,-39.85C236.93,250 229.74,234.57 215.51,222.49z"""

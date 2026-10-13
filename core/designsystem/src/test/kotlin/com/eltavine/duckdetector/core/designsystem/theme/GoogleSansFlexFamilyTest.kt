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

package com.eltavine.duckdetector.core.designsystem.theme

import androidx.compose.ui.text.font.FontListFontFamily
import androidx.compose.ui.text.font.ResourceFont
import org.junit.Assert.assertEquals
import org.junit.Test

class GoogleSansFlexFamilyTest {
    @Test
    fun everyWeightSetsTheWeightAxisToThatWeight() {
        val fonts = (GoogleSansFlexFamily as FontListFontFamily).fonts

        assertEquals((400..900 step 100).toList(), fonts.map { it.weight.weight })
        fonts.forEach { font ->
            val settings = (font as ResourceFont).variationSettings.settings
            assertEquals("${font.weight}", listOf("wght"), settings.map { it.axisName })
            assertEquals(
                "${font.weight}",
                font.weight.weight.toFloat(),
                settings.single().toVariationValue(null),
                0f,
            )
        }
    }
}

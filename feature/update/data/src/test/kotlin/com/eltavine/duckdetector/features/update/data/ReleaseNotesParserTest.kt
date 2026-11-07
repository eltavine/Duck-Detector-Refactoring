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

package com.eltavine.duckdetector.features.update.data

import com.eltavine.duckdetector.features.update.domain.ReleaseNotesItem
import com.eltavine.duckdetector.features.update.domain.ReleaseNotesSection
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ReleaseNotesParserTest {
    private val parser = ReleaseNotesParser()

    @Test
    fun `reads GitHub generated notes into sections of changes`() {
        val sections = parser.parse(TEST_RELEASE_NOTES)

        assertEquals(
            listOf(
                ReleaseNotesSection(
                    title = "What's Changed",
                    items = listOf(
                        ReleaseNotesItem("build: turn off the alpha build flag", author = "eltavine", pullRequest = 151),
                        ReleaseNotesItem(
                            "fix(tee): skip RSA OAEP MGF1 checks on legacy devices",
                            author = "salvogiangri",
                            pullRequest = 80,
                        ),
                    ),
                ),
                ReleaseNotesSection(
                    title = "New Contributors",
                    items = listOf(ReleaseNotesItem("@cwuom made their first contribution", pullRequest = 146)),
                ),
            ),
            sections,
        )
    }

    @Test
    fun `keeps hand-written lines and strips Markdown markers`() {
        val sections = parser.parse(
            """
            Highlights for **Stable** users.

            ### Fixes
            - Stop `probes` from crashing \<apps\>
            * Title with by @words in the middle by @dependabot[bot] in https://github.com/o/r/pull/7
            """.trimIndent(),
        )

        assertEquals(listOf(null, "Fixes"), sections.map { it.title })
        assertEquals("Highlights for Stable users.", sections[0].items.single().text)
        assertEquals("Stop probes from crashing <apps>", sections[1].items[0].text)
        assertEquals(
            ReleaseNotesItem("Title with by @words in the middle", author = "dependabot[bot]", pullRequest = 7),
            sections[1].items[1],
        )
    }

    @Test
    fun `empty notes have no sections`() {
        assertTrue(parser.parse("").isEmpty())
        assertTrue(parser.parse("**Full Changelog**: https://github.com/o/r/commits/v26.10.0").isEmpty())
    }
}

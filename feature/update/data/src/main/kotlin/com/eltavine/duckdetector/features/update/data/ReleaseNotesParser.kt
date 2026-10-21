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

/**
 * Reads the Markdown GitHub generates for a release: sections such as "What's Changed" and "New
 * Contributors" whose bullets read `<title> by @<login> in <pull request URL>`, closed by a Full
 * Changelog link. Headings open sections and bullets become items; any other line is kept as an item
 * of its own, so notes written by hand still show. The Full Changelog line is dropped because the
 * dialog links the release page.
 */
internal class ReleaseNotesParser {

    fun parse(markdown: String): List<ReleaseNotesSection> {
        val sections = mutableListOf<ReleaseNotesSection>()
        var title: String? = null
        var items = mutableListOf<ReleaseNotesItem>()
        fun closeSection() {
            if (items.isNotEmpty()) {
                sections += ReleaseNotesSection(title = title, items = items)
            }
            items = mutableListOf()
        }

        markdown.lineSequence().map(String::trim).forEach { line ->
            val heading = HEADING.matchEntire(line)
            val bullet = BULLET.matchEntire(line)
            when {
                line.isEmpty() || FULL_CHANGELOG.containsMatchIn(line) -> Unit
                heading != null -> {
                    closeSection()
                    title = heading.groupValues[1].plainText()
                }
                bullet != null -> items += item(bullet.groupValues[1])
                else -> items += ReleaseNotesItem(text = line.plainText())
            }
        }
        closeSection()
        return sections
    }

    private fun item(text: String): ReleaseNotesItem {
        CHANGE.matchEntire(text)?.let { change ->
            return ReleaseNotesItem(
                text = change.groupValues[1].plainText(),
                author = change.groupValues[2],
                pullRequest = change.groupValues[3].toIntOrNull(),
            )
        }
        FIRST_CONTRIBUTION.matchEntire(text)?.let { contribution ->
            return ReleaseNotesItem(
                text = "@${contribution.groupValues[1]} ${contribution.groupValues[2]}",
                pullRequest = contribution.groupValues[3].toIntOrNull(),
            )
        }
        return ReleaseNotesItem(text = text.plainText())
    }

    private fun String.plainText(): String =
        replace(EMPHASIS, "").replace(ESCAPED, "$1").trim()

    private companion object {
        private const val LOGIN = """([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\[bot])?)"""
        private const val PULL_REQUEST_URL = """https://github\.com/[^/\s]+/[^/\s]+/pull/(\d+)"""
        private val HEADING = Regex("""#{1,6}\s+(.+)""")
        private val BULLET = Regex("""[*-]\s+(.+)""")
        private val CHANGE = Regex("""(.+?) by @$LOGIN in $PULL_REQUEST_URL""")
        private val FIRST_CONTRIBUTION = Regex("""@$LOGIN (made their first contribution) in $PULL_REQUEST_URL""")
        private val FULL_CHANGELOG = Regex("""^\*\*Full Changelog\*\*""")
        private val EMPHASIS = Regex("""\*\*|__|`""")
        private val ESCAPED = Regex("""\\([\\`*_\[\]<>|#])""")
    }
}

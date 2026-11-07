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

import org.json.JSONArray
import org.json.JSONObject

internal const val TEST_HEAD_SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
internal const val TEST_BASE_SHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
internal const val TEST_DOWNLOAD_URL =
    "https://github.com/eltavine/Duck-Detector-Refactoring/releases/download/nightly/Duck.Detector-test.apk"
internal const val TEST_STABLE_TAG = "v26.10.0"
internal const val TEST_STABLE_DOWNLOAD_URL =
    "https://github.com/eltavine/Duck-Detector-Refactoring/releases/download/v26.10.0/Duck.Detector-26.10.0.apk"
internal const val TEST_RELEASE_URL =
    "https://github.com/eltavine/Duck-Detector-Refactoring/releases/tag/v26.10.0"

// The shape GitHub's generate-notes endpoint returned for this repository.
internal val TEST_RELEASE_NOTES = """
    ## What's Changed
    * build: turn off the alpha build flag by @eltavine in https://github.com/eltavine/Duck-Detector-Refactoring/pull/151
    * fix(tee): skip RSA OAEP MGF1 checks on legacy devices by @salvogiangri in https://github.com/eltavine/Duck-Detector-Refactoring/pull/80

    ## New Contributors
    * @cwuom made their first contribution in https://github.com/eltavine/Duck-Detector-Refactoring/pull/146

    **Full Changelog**: https://github.com/eltavine/Duck-Detector-Refactoring/commits/v26.10.0
""".trimIndent()

internal fun validUpdateManifestJson(
    versionCode: Int = 500,
    commitSha: String = TEST_HEAD_SHA,
    builtAtUtc: String = "2026-08-08T12:30:00Z",
    branch: String = "master",
    downloadUrl: String = TEST_DOWNLOAD_URL,
    changes: JSONObject? = null,
): String {
    return JSONObject()
        .put("schemaVersion", 1)
        .put("channel", "nightly")
        .put("branch", branch)
        .put("versionName", "2026.08.08-${commitSha.take(12)}")
        .put("versionCode", versionCode)
        .put("commit", commitJson(commitSha))
        .put("builtAtUtc", builtAtUtc)
        .put("apk", apkJson("Duck.Detector-test.apk", downloadUrl))
        .apply { changes?.let { put("changes", it) } }
        .toString()
}

internal fun validStableManifestJson(
    versionCode: Int = 500,
    commitSha: String = TEST_HEAD_SHA,
    tag: String = TEST_STABLE_TAG,
    versionName: String = tag.removePrefix("v"),
    releaseUrl: String = TEST_RELEASE_URL,
    downloadUrl: String = TEST_STABLE_DOWNLOAD_URL,
    notes: String = TEST_RELEASE_NOTES,
): String {
    return JSONObject()
        .put("schemaVersion", 1)
        .put("channel", "stable")
        .put("branch", "main")
        .put("versionName", versionName)
        .put("versionCode", versionCode)
        .put("commit", commitJson(commitSha))
        .put("builtAtUtc", "2026-10-01T08:30:00Z")
        .put("apk", apkJson("Duck.Detector-26.10.0.apk", downloadUrl))
        .put(
            "release",
            JSONObject()
                .put("tag", tag)
                .put("url", releaseUrl)
                .put("notes", notes),
        )
        .toString()
}

/** Changes after [baseSha], newest first, as release_changes.py lists them. */
internal fun changesJson(
    entries: List<String>,
    totalCount: Int = entries.size,
    baseTag: String? = TEST_STABLE_TAG,
    baseSha: String? = TEST_BASE_SHA,
): JSONObject {
    val array = JSONArray()
    entries.forEachIndexed { index, sha ->
        array.put(
            JSONObject()
                .put("sha", sha)
                .put("subject", "Change $index")
                .put("authorName", "Contributor $index")
                .put("pullRequest", if (index % 2 == 0) 100 + index else JSONObject.NULL),
        )
    }
    return JSONObject()
        .put("baseTag", baseTag ?: JSONObject.NULL)
        .put("baseSha", baseSha ?: JSONObject.NULL)
        .put("totalCount", totalCount)
        .put("entries", array)
}

private fun commitJson(commitSha: String): JSONObject {
    return JSONObject()
        .put("sha", commitSha)
        .put("subject", "feat(update): publish Nightly metadata")
        .put("body", "Publish metadata after the APK is available.")
        .put("authorName", "Duck Contributor")
        .put("authoredAt", "2026-08-08T12:20:00Z")
}

private fun apkJson(name: String, downloadUrl: String): JSONObject {
    return JSONObject()
        .put("name", name)
        .put("downloadUrl", downloadUrl)
        .put("sizeBytes", 12_345_678L)
        .put("sha256", "c".repeat(64))
}

internal fun compareResponseJson(
    totalCommits: Int,
    commits: List<TestCompareCommit>,
): String {
    val commitArray = JSONArray()
    commits.forEach { item ->
        val parents = JSONArray().put(JSONObject().put("sha", "d".repeat(40)))
        if (item.isMerge) {
            parents.put(JSONObject().put("sha", "e".repeat(40)))
        }
        commitArray.put(
            JSONObject()
                .put("sha", item.sha)
                .put("parents", parents)
                .put(
                    "commit",
                    JSONObject()
                        .put("message", "${item.subject}\nCommit body")
                        .put("author", JSONObject().put("name", item.author)),
                ),
        )
    }
    return JSONObject()
        .put("total_commits", totalCommits)
        .put("commits", commitArray)
        .toString()
}

internal data class TestCompareCommit(
    val sha: String,
    val subject: String,
    val author: String = "Contributor",
    val isMerge: Boolean = false,
)

internal fun testCommit(index: Int, isMerge: Boolean = false): TestCompareCommit {
    return TestCompareCommit(
        sha = index.toString(16).padStart(40, '0'),
        subject = "Commit $index",
        isMerge = isMerge,
    )
}

/** Full SHAs whose abbreviations differ, as BuildConfig's 12-character hashes of distinct commits do. */
internal fun testSha(index: Int): String = index.toString(16).padEnd(40, 'f')

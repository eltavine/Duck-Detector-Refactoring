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

package com.eltavine.duckdetector.features.kernelcheck.data.repository

import android.os.Build
import com.eltavine.duckdetector.features.kernelcheck.data.native.KernelCheckNativeBridge
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckFinding
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckCvePatchState
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckFindingSeverity
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckMethodOutcome
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckMethodResult
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckReport
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckStage
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class KernelCheckRepository(
    private val nativeBridge: KernelCheckNativeBridge = KernelCheckNativeBridge(),
) {

    suspend fun scan(): KernelCheckReport = withContext(Dispatchers.IO) {
        runCatching { scanInternal() }
            .getOrElse { throwable ->
                KernelCheckReport.failed(throwable.message ?: "Kernel Check scan failed.")
            }
    }

    private fun scanInternal(): KernelCheckReport {
        val unameOutput = getUnameOutput()
        val nativeSnapshot = nativeBridge.collectSnapshot(Build.TIME)
        val procVersion = nativeSnapshot.procVersion.ifBlank { readFileText("/proc/version") }
        val procCmdline = nativeSnapshot.procCmdline.ifBlank {
            readFileText("/proc/cmdline").replace(
                '\u0000',
                ' '
            )
        }
        val identitySources = listOf(unameOutput, procVersion)
            .filter { it.isNotBlank() }
            .distinct()

        if (identitySources.isEmpty() && procCmdline.isBlank() && !nativeSnapshot.available) {
            return KernelCheckReport.failed(
                "Unable to read kernel identity through uname -a or /proc/version.",
            )
        }

        val combinedIdentity = identitySources.joinToString(separator = "\n")

        val emojiFinding = findEmojis(combinedIdentity)
            .takeIf { it.isNotEmpty() }
            ?.let {
                KernelCheckFinding(
                    id = "emoji",
                    label = "Emoji markers",
                    value = it.joinToString(" "),
                    detail = "Kernel identity contains emoji codepoints.",
                    severity = KernelCheckFindingSeverity.HARD,
                )
            }

        val chineseCharFinding = findChineseCharacters(combinedIdentity)
            .takeIf { it.isNotEmpty() }
            ?.let {
                KernelCheckFinding(
                    id = "chinese_chars",
                    label = "Chinese glyphs",
                    value = it.joinToString(""),
                    detail = "Kernel identity contains CJK characters.",
                    severity = KernelCheckFindingSeverity.HARD,
                )
            }

        val nonLatinScriptResult = findNonLatinScriptCharacters(combinedIdentity)
        val nonLatinScriptFinding = nonLatinScriptResult.samples
            .takeIf { it.isNotEmpty() }
            ?.let {
                KernelCheckFinding(
                    id = "non_latin_scripts",
                    label = "Other language scripts",
                    value = nonLatinScriptResult.scriptNames.joinToString(", "),
                    detail = buildString {
                        append("Kernel identity contains non-Latin script characters")
                        if (nonLatinScriptResult.scriptNames.isNotEmpty()) {
                            append(": ")
                            append(nonLatinScriptResult.scriptNames.joinToString(", "))
                        }
                        if (nonLatinScriptResult.samples.isNotEmpty()) {
                            append(". Samples: ")
                            append(nonLatinScriptResult.samples.joinToString(" "))
                        }
                        append(".")
                    },
                    severity = KernelCheckFindingSeverity.HARD,
                )
            }

        val telegramFinding = TELEGRAM_REGEX.findAll(combinedIdentity)
            .map { it.value }
            .distinct()
            .toList()
            .takeIf { it.isNotEmpty() }
            ?.let {
                KernelCheckFinding(
                    id = "telegram_ref",
                    label = "Telegram reference",
                    value = it.joinToString(", "),
                    detail = "Kernel identity references TG/Telegram style handles or channels.",
                    severity = KernelCheckFindingSeverity.HARD,
                )
            }

        val mentionFinding = MENTION_REGEX.findAll(combinedIdentity)
            .map { it.value }
            .distinct()
            .toList()
            .takeIf { it.isNotEmpty() }
            ?.let {
                KernelCheckFinding(
                    id = "at_mention",
                    label = "@ mentions",
                    value = it.joinToString(", "),
                    detail = "Kernel identity contains maintainer-style @ mentions.",
                    severity = KernelCheckFindingSeverity.HARD,
                )
            }

        val customKeywordFinding = detectCustomKernelKeywords(combinedIdentity)
            .takeIf { it.isNotEmpty() }
            ?.let {
                KernelCheckFinding(
                    id = "custom_kernel",
                    label = "Custom identifiers",
                    value = it.joinToString(", "),
                    detail = "Known community kernel identifiers matched the kernel identity.",
                    severity = KernelCheckFindingSeverity.HARD,
                )
            }

        val cmdlineMatches = nativeSnapshot.findings.details("CMDLINE|CRITICAL|")
            .ifEmpty { detectCriticalCmdlineFallback(procCmdline) }
        val cmdlineFinding = cmdlineMatches
            .takeIf { it.isNotEmpty() }
            ?.let {
                KernelCheckFinding(
                    id = "suspicious_cmdline",
                    label = "Boot cmdline",
                    value = "${it.size} hit(s)",
                    detail = it.joinToString(separator = "\n"),
                    severity = KernelCheckFindingSeverity.HARD,
                )
            }

        val buildTimeDetail = nativeSnapshot.findings.firstDetail("BUILD_TIME|MISMATCH|")
            ?: detectBuildTimeMismatchFallback(
                unameOutput = unameOutput,
                procVersion = procVersion,
                systemBuildTime = Build.TIME,
            )
        val buildTimeFinding = buildTimeDetail
            ?.let {
                KernelCheckFinding(
                    id = "build_time_mismatch",
                    label = "Build time drift",
                    value = "Mismatch",
                    detail = it,
                    severity = KernelCheckFindingSeverity.HARD,
                )
            }

        val kptrDetail = nativeSnapshot.findings.firstDetail("KPTR_RESTRICT|DISABLED|")
        val kptrFinding = (kptrDetail ?: "kptr_restrict appears disabled.")
            .takeIf { kptrDetail != null || nativeSnapshot.kptrExposed }
            ?.let {
                KernelCheckFinding(
                    id = "kptr_exposed",
                    label = "Kernel pointers",
                    value = "Exposed",
                    detail = it,
                    severity = KernelCheckFindingSeverity.INFO,
                )
            }

        val cveAssessment = detectCvePatchState()
        val cveFinding = cveAssessment
            .takeIf {
                it.state in setOf(
                    KernelCheckCvePatchState.UNPATCHED,
                    KernelCheckCvePatchState.PARTIALLY_PATCHED,
                )
            }
            ?.let {
                KernelCheckFinding(
                    id = "cve_patch_state",
                    label = "CVE-2024-43093",
                    value = it.state.label,
                    detail = it.detail,
                    severity = KernelCheckFindingSeverity.INFO,
                )
            }

        val dangerFindings = listOfNotNull(
            emojiFinding,
            chineseCharFinding,
            nonLatinScriptFinding,
            telegramFinding,
            mentionFinding,
            customKeywordFinding,
            cmdlineFinding,
            buildTimeFinding,
        )

        val infoFindings = listOfNotNull(kptrFinding, cveFinding)

        val methods = buildMethods(
            dangerFindings = dangerFindings,
            infoFindings = infoFindings,
            cveAssessment = cveAssessment,
            nativeAvailable = nativeSnapshot.available,
        )

        return KernelCheckReport(
            stage = KernelCheckStage.READY,
            unameOutput = unameOutput,
            procVersion = procVersion,
            procCmdline = procCmdline,
            dangerFindings = dangerFindings,
            infoFindings = infoFindings,
            suspiciousCmdline = cmdlineMatches.isNotEmpty(),
            buildTimeMismatch = buildTimeDetail != null,
            kptrExposed = kptrDetail != null || nativeSnapshot.kptrExposed,
            cvePatchState = cveAssessment.state,
            cvePatchDetail = cveAssessment.detail,
            nativeAvailable = nativeSnapshot.available,
            checkedKeywordCount = KEYWORD_SCAN_COUNT,
            checkedCmdlineRuleCount = CMDLINE_CHECKS.size,
            methods = methods,
        )
    }

    private fun buildMethods(
        dangerFindings: List<KernelCheckFinding>,
        infoFindings: List<KernelCheckFinding>,
        cveAssessment: CvePatchAssessment,
        nativeAvailable: Boolean,
    ): List<KernelCheckMethodResult> {
        val dangerById = dangerFindings.associateBy { it.id }
        val infoById = infoFindings.associateBy { it.id }

        return listOf(
            buildNamingMethod("emojiScan", dangerById["emoji"]),
            buildNamingMethod("chineseScan", dangerById["chinese_chars"]),
            buildNamingMethod("scriptScan", dangerById["non_latin_scripts"]),
            buildNamingMethod("telegramScan", dangerById["telegram_ref"]),
            buildNamingMethod("mentionScan", dangerById["at_mention"]),
            buildNamingMethod("customKernel", dangerById["custom_kernel"]),
            buildNativeMethod(
                "cmdlineCheck",
                dangerById["suspicious_cmdline"],
                nativeAvailable,
                "Normal"
            ),
            buildNativeMethod(
                "buildTime",
                dangerById["build_time_mismatch"],
                nativeAvailable,
                "OK"
            ),
            buildCveMethod("cvePatchCheck", cveAssessment),
            buildInfoMethod(
                "kptrRestrict",
                infoById["kptr_exposed"],
                unavailable = !nativeAvailable
            ),
            KernelCheckMethodResult(
                label = "nativeLibrary",
                summary = if (nativeAvailable) "Loaded" else "Unavailable",
                outcome = if (nativeAvailable) KernelCheckMethodOutcome.CLEAN else KernelCheckMethodOutcome.SUPPORT,
            ),
        )
    }

    private fun buildNamingMethod(
        label: String,
        finding: KernelCheckFinding?,
    ): KernelCheckMethodResult {
        return KernelCheckMethodResult(
            label = label,
            summary = finding?.value ?: "Clean",
            outcome = if (finding != null) {
                KernelCheckMethodOutcome.DETECTED
            } else {
                KernelCheckMethodOutcome.CLEAN
            },
            detail = finding?.detail,
        )
    }

    private fun buildNativeMethod(
        label: String,
        finding: KernelCheckFinding?,
        nativeAvailable: Boolean,
        cleanSummary: String,
    ): KernelCheckMethodResult {
        return when {
            finding != null -> KernelCheckMethodResult(
                label = label,
                summary = finding.value,
                outcome = KernelCheckMethodOutcome.DETECTED,
                detail = finding.detail,
            )

            nativeAvailable -> KernelCheckMethodResult(
                label = label,
                summary = cleanSummary,
                outcome = KernelCheckMethodOutcome.CLEAN,
            )

            else -> KernelCheckMethodResult(
                label = label,
                summary = "Unavailable",
                outcome = KernelCheckMethodOutcome.SUPPORT,
            )
        }
    }

    private fun buildCveMethod(
        label: String,
        assessment: CvePatchAssessment,
    ): KernelCheckMethodResult {
        return KernelCheckMethodResult(
            label = label,
            summary = assessment.state.label,
            outcome = when (assessment.state) {
                KernelCheckCvePatchState.UNPATCHED,
                KernelCheckCvePatchState.PARTIALLY_PATCHED -> KernelCheckMethodOutcome.INFO

                KernelCheckCvePatchState.PATCHED -> KernelCheckMethodOutcome.CLEAN
                KernelCheckCvePatchState.INCONCLUSIVE -> KernelCheckMethodOutcome.SUPPORT
            },
            detail = assessment.detail,
        )
    }

    private fun buildInfoMethod(
        label: String,
        finding: KernelCheckFinding?,
        unavailable: Boolean = false,
    ): KernelCheckMethodResult {
        return when {
            finding != null -> KernelCheckMethodResult(
                label = label,
                summary = finding.value,
                outcome = KernelCheckMethodOutcome.INFO,
                detail = finding.detail,
            )

            unavailable -> KernelCheckMethodResult(
                label = label,
                summary = "Unavailable",
                outcome = KernelCheckMethodOutcome.SUPPORT,
            )

            else -> KernelCheckMethodResult(
                label = label,
                summary = "OK",
                outcome = KernelCheckMethodOutcome.CLEAN,
            )
        }
    }

    private fun detectCustomKernelKeywords(
        input: String,
    ): List<String> =
        input.takeUnless(String::isBlank)
            ?.let { identity ->
                KERNEL_KEYWORD_RULES
                    .filter { it.matches(identity) }
                    .map { it.keyword }
            }
            .orEmpty()

    private fun detectCriticalCmdlineFallback(
        procCmdline: String,
    ): List<String> =
        procCmdline.takeUnless(String::isBlank)
            ?.let { cmdline ->
                CMDLINE_CHECKS
                    .filter {
                        it.isCritical && cmdline.contains(
                            it.pattern,
                            ignoreCase = true,
                        )
                    }
                    .map { it.description }
            }
            .orEmpty()

    private fun detectBuildTimeMismatchFallback(
        unameOutput: String,
        procVersion: String,
        systemBuildTime: Long,
    ): String? {
        if (systemBuildTime <= 0L) {
            return null
        }
        val sources = listOf(
            "uname -a" to unameOutput,
            "/proc/version" to procVersion,
        )
        val parser = SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.US)
        return sources
            .asSequence()
            .filter { (_, text) -> text.isNotBlank() }
            .mapNotNull { (label, text) ->
                BUILD_TIME_REGEX.find(text)
                    ?.value
                    ?.replace(Regex("\\s+"), " ")
                    ?.let { kernelDateText ->
                        runCatching { parser.parse(kernelDateText) }
                            .getOrNull()
                            ?.let { kernelDate -> label to kernelDate }
                    }
            }
            .map { (label, kernelDate) ->
                val diffDays = TimeUnit.MILLISECONDS.toDays(kernelDate.time - systemBuildTime)
                val systemDate = SimpleDateFormat("yyyy-MM-dd", Locale.US).format(Date(systemBuildTime))
                val kernelDateShort = SimpleDateFormat("yyyy-MM-dd", Locale.US).format(kernelDate)

                Triple(label, kernelDateShort, systemDate) to diffDays
            }
            .firstOrNull { (_, diffDays) -> diffDays !in -365L..30L }
            ?.let { (dates, diffDays) ->
                val (label, kernelDateShort, systemDate) = dates
                "$label -> Kernel: $kernelDateShort, System: $systemDate (diff: $diffDays days)"
            }
    }

    private fun getUnameOutput(): String {
        return executeCommand("uname", "-a")
            .ifBlank { readFileText("/proc/version") }
    }

    private fun executeCommand(
        vararg command: String,
    ): String {
        var process: Process? = null
        return try {
            process = ProcessBuilder(*command)
                .redirectErrorStream(true)
                .start()
            val output = process.inputStream.bufferedReader().use { it.readText().trim() }
            if (!process.waitFor(PROCESS_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                process.destroyForcibly()
                ""
            } else {
                output
            }
        } catch (_: Exception) {
            ""
        } finally {
            process?.destroy()
        }
    }

    private fun readFileText(
        path: String,
    ): String {
        return try {
            val file = File(path)
            if (!file.exists() || !file.canRead()) {
                ""
            } else {
                file.readText().trim().replace('\u0000', ' ')
            }
        } catch (_: Exception) {
            ""
        }
    }

    private fun findEmojis(
        text: String,
    ): List<String> =
        text.codePointSequence()
            .filter(::isEmoji)
            .map(::codePointToString)
            .distinct()
            .toList()

    private fun isEmoji(
        codePoint: Int,
    ): Boolean {
        return when (codePoint) {
            in 0x1F600..0x1F64F,
            in 0x1F300..0x1F5FF,
            in 0x1F680..0x1F6FF,
            in 0x1F900..0x1F9FF,
            in 0x1FA00..0x1FA6F,
            in 0x1FA70..0x1FAFF,
            in 0x2700..0x27BF,
            in 0x2600..0x26FF,
            in 0x1F1E0..0x1F1FF -> true

            else -> false
        }
    }

    private fun findChineseCharacters(
        text: String,
    ): List<String> =
        text.codePointSequence()
            .filter(::isChineseCharacter)
            .map(::codePointToString)
            .distinct()
            .toList()

    private fun isChineseCharacter(
        codePoint: Int,
    ): Boolean {
        return when (codePoint) {
            in 0x4E00..0x9FFF,
            in 0x3400..0x4DBF,
            in 0x20000..0x2A6DF,
            in 0x2A700..0x2B73F,
            in 0x2B740..0x2B81F,
            in 0x2B820..0x2CEAF,
            in 0xF900..0xFAFF,
            in 0x2F800..0x2FA1F -> true

            else -> false
        }
    }

    private fun findNonLatinScriptCharacters(
        text: String,
    ): NonLatinScriptScanResult =
        text.codePointSequence()
            .filter(::isUnexpectedNonLatinScript)
            .toList()
            .let { codePoints ->
                NonLatinScriptScanResult(
                    scriptNames = codePoints
                        .map { Character.UnicodeScript.of(it) }
                        .map(::unicodeScriptLabel)
                        .distinct(),
                    samples = codePoints
                        .map(::codePointToString)
                        .distinct()
                        .take(MAX_SCRIPT_SAMPLE_COUNT),
                )
            }

    private fun isUnexpectedNonLatinScript(
        codePoint: Int,
    ): Boolean =
        Character.isLetter(codePoint) && when (Character.UnicodeScript.of(codePoint)) {
            Character.UnicodeScript.LATIN,
            Character.UnicodeScript.COMMON,
            Character.UnicodeScript.INHERITED,
            Character.UnicodeScript.HAN -> false

            else -> true
        }

    private fun unicodeScriptLabel(
        script: Character.UnicodeScript,
    ): String {
        return when (script) {
            Character.UnicodeScript.ARABIC -> "Arabic"
            Character.UnicodeScript.ARMENIAN -> "Armenian"
            Character.UnicodeScript.BENGALI -> "Bengali"
            Character.UnicodeScript.CYRILLIC -> "Cyrillic"
            Character.UnicodeScript.DEVANAGARI -> "Devanagari"
            Character.UnicodeScript.ETHIOPIC -> "Ethiopic"
            Character.UnicodeScript.GEORGIAN -> "Georgian"
            Character.UnicodeScript.GREEK -> "Greek"
            Character.UnicodeScript.GUJARATI -> "Gujarati"
            Character.UnicodeScript.GURMUKHI -> "Gurmukhi"
            Character.UnicodeScript.HANGUL -> "Hangul"
            Character.UnicodeScript.HEBREW -> "Hebrew"
            Character.UnicodeScript.HIRAGANA -> "Hiragana"
            Character.UnicodeScript.KANNADA -> "Kannada"
            Character.UnicodeScript.KATAKANA -> "Katakana"
            Character.UnicodeScript.KHMER -> "Khmer"
            Character.UnicodeScript.LAO -> "Lao"
            Character.UnicodeScript.MALAYALAM -> "Malayalam"
            Character.UnicodeScript.MYANMAR -> "Myanmar"
            Character.UnicodeScript.ORIYA -> "Oriya"
            Character.UnicodeScript.SINHALA -> "Sinhala"
            Character.UnicodeScript.TAMIL -> "Tamil"
            Character.UnicodeScript.TELUGU -> "Telugu"
            Character.UnicodeScript.THAI -> "Thai"
            else -> script.name.lowercase()
                .split('_')
                .joinToString(" ") { part ->
                    part.replaceFirstChar { char -> char.uppercase() }
                }
        }
    }

    private fun String.codePointSequence(): Sequence<Int> =
        takeIf { it.isNotEmpty() }
            ?.let { text ->
                generateSequence(0) { index ->
                    (index + Character.charCount(text.codePointAt(index)))
                        .takeIf { it < text.length }
                }.map(text::codePointAt)
            }
            ?: emptySequence()

    private fun codePointToString(
        codePoint: Int,
    ): String = String(Character.toChars(codePoint))

    private fun detectCvePatchState(): CvePatchAssessment {
        val targetPath = "/sdcard/Android/data"
        val zwcProbe = testUnicodeBypass(
            basePath = targetPath,
            bypassChar = "\u200B",
            bypassName = "Zero Width Space",
        )
        val otherIgnorableChars = listOf(
            "\u00AD" to "Soft Hyphen",
            "\u034F" to "Combining Grapheme Joiner",
            "\u200C" to "Zero Width Non-Joiner",
            "\u200D" to "Zero Width Joiner",
            "\u2060" to "Word Joiner",
            "\uFEFF" to "BOM/ZWNBSP",
            "\u180E" to "Mongolian Vowel Separator",
        )

        val otherProbes = otherIgnorableChars.map { (char, name) ->
            char to testUnicodeBypass(
                basePath = targetPath,
                bypassChar = char,
                bypassName = name,
            )
        }
        val workingProbe = otherProbes.firstOrNull { (_, probe) ->
            probe.state == UnicodeBypassState.BYPASSED
        }
        val inconclusiveProbe = otherProbes.firstOrNull { (_, probe) ->
            probe.state == UnicodeBypassState.INCONCLUSIVE
        }?.second

        return when {
            zwcProbe.state == UnicodeBypassState.BYPASSED && workingProbe != null -> {
                val (char, probe) = workingProbe
                CvePatchAssessment(
                    state = KernelCheckCvePatchState.UNPATCHED,
                    detail = buildString {
                        append("ZWC and ")
                        append(probe.bypassName)
                        append(" (U+")
                        append(char.codePointAt(0).toString(16).uppercase())
                        append(") still bypass the path filter.")
                    },
                )
            }

            zwcProbe.state == UnicodeBypassState.BLOCKED && workingProbe != null -> {
                val (char, probe) = workingProbe
                CvePatchAssessment(
                    state = KernelCheckCvePatchState.PARTIALLY_PATCHED,
                    detail = buildString {
                        append("ZWC is blocked, but ")
                        append(probe.bypassName)
                        append(" (U+")
                        append(char.codePointAt(0).toString(16).uppercase())
                        append(") still bypasses the path filter.")
                    },
                )
            }

            zwcProbe.state == UnicodeBypassState.BLOCKED &&
                    otherProbes.all { (_, probe) -> probe.state == UnicodeBypassState.BLOCKED } -> {
                CvePatchAssessment(
                    state = KernelCheckCvePatchState.PATCHED,
                    detail = "ZWC and ${otherProbes.size} tested ignorable codepoints were blocked.",
                )
            }

            zwcProbe.state == UnicodeBypassState.BYPASSED &&
                    otherProbes.all { (_, probe) -> probe.state == UnicodeBypassState.BLOCKED } -> {
                CvePatchAssessment(
                    state = KernelCheckCvePatchState.INCONCLUSIVE,
                    detail = "ZWC bypassed, but the other tested ignorable codepoints did not. The result does not fit a stable patched or unpatched pattern.",
                )
            }

            zwcProbe.state == UnicodeBypassState.INCONCLUSIVE -> {
                CvePatchAssessment(
                    state = KernelCheckCvePatchState.INCONCLUSIVE,
                    detail = zwcProbe.detail
                        ?: "The ZWC bypass probe could not produce a stable result.",
                )
            }

            inconclusiveProbe != null -> {
                CvePatchAssessment(
                    state = KernelCheckCvePatchState.INCONCLUSIVE,
                    detail = inconclusiveProbe.detail
                        ?: "One or more ignorable-codepoint probes could not produce a stable result.",
                )
            }

            else -> {
                CvePatchAssessment(
                    state = KernelCheckCvePatchState.INCONCLUSIVE,
                    detail = "The bypass probes did not produce enough stable evidence to determine patch state.",
                )
            }
        }
    }

    private fun testUnicodeBypass(
        basePath: String,
        bypassChar: String,
        bypassName: String,
    ): UnicodeBypassProbe {
        val baseProbe = runListProbe("$basePath/")
        if (baseProbe.succeeded) {
            return UnicodeBypassProbe(
                state = UnicodeBypassState.INCONCLUSIVE,
                bypassName = bypassName,
                detail = "The base Android/data path is directly listable, so bypass status cannot be inferred from this probe.",
            )
        }

        val bypassPaths = listOf(
            "$basePath$bypassChar/",
            "$basePath/$bypassChar",
        )

        val bypassProbes = bypassPaths.map(::runListProbe)

        return when {
            bypassProbes.any { it.succeeded } ->
                UnicodeBypassProbe(
                    state = UnicodeBypassState.BYPASSED,
                    bypassName = bypassName,
                    detail = "$bypassName successfully bypassed the path filter.",
                )

            bypassProbes.any { it.completed } ->
                UnicodeBypassProbe(
                    state = UnicodeBypassState.BLOCKED,
                    bypassName = bypassName,
                    detail = "$bypassName was blocked by the path filter.",
                )

            else ->
                UnicodeBypassProbe(
                    state = UnicodeBypassState.INCONCLUSIVE,
                    bypassName = bypassName,
                    detail = "The $bypassName probe could not execute reliably.",
                )
        }
    }

    private fun runListProbe(
        path: String,
    ): DirectoryListProbe {
        var process: Process? = null
        return try {
            process = ProcessBuilder("ls", path)
                .redirectErrorStream(true)
                .start()
            process.inputStream.bufferedReader().use { it.readText() }
            if (!process.waitFor(UNICODE_TEST_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                process.destroyForcibly()
                DirectoryListProbe(
                    completed = false,
                    exitCode = null,
                )
            } else {
                DirectoryListProbe(
                    completed = true,
                    exitCode = process.exitValue(),
                )
            }
        } catch (_: Exception) {
            DirectoryListProbe(
                completed = false,
                exitCode = null,
            )
        } finally {
            process?.destroy()
        }
    }

    private fun List<String>.firstDetail(
        prefix: String,
    ): String? {
        return firstOrNull { it.startsWith(prefix) }?.substringAfter(prefix)
            ?.takeIf { it.isNotBlank() }
    }

    private fun List<String>.details(
        prefix: String,
    ): List<String> {
        return filter { it.startsWith(prefix) }
            .mapNotNull { it.substringAfter(prefix).takeIf { detail -> detail.isNotBlank() } }
    }

    companion object {
        private const val PROCESS_TIMEOUT_SECONDS = 2L
        private const val UNICODE_TEST_TIMEOUT_SECONDS = 2L
        private const val MAX_SCRIPT_SAMPLE_COUNT = 8

        private val TELEGRAM_REGEX =
            Regex("""\bTG\b|\bTelegram\b|t\.me/""", RegexOption.IGNORE_CASE)

        private val MENTION_REGEX = Regex("@[A-Za-z0-9_]+")

        private val BUILD_TIME_REGEX =
            Regex("""\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\w+\s+\d{4}""")

        private val KERNEL_KEYWORD_RULES = listOf(
            "kernelsu", "sukisu", "apatch", 
            "shirkneko", "mirinfork", "brokestar",
            "xiaoxiaow", "qdykernel", "numbers", "cctv",
            "arter97", "blu_spark", "elementalx", "franco", 
            "kirisakura", "sultan", "weeb", "nethunter",
            "aptkernel", "coolzyd9107", "aptusitu", "Glow-v"
        ).map { keyword ->
            KernelKeywordRule(keyword = keyword, ignoreCase = true)
        } + listOf(
            KernelKeywordRule(keyword = "OKI", ignoreCase = false, wholeWord = true),

        private val KEYWORD_SCAN_COUNT = KERNEL_KEYWORD_RULES.size + 5

        private val CMDLINE_CHECKS = listOf(
            CmdlineCheck("androidboot.verifiedbootstate=orange", "Bootloader unlocked (orange)", isCritical = true),
            CmdlineCheck("androidboot.verifiedbootstate=yellow", "Self-signed boot (yellow)", isCritical = true),
            CmdlineCheck("androidboot.enable_dm_verity=0", "dm-verity disabled", isCritical = true),
            CmdlineCheck("androidboot.secboot=disabled", "Secure boot disabled", isCritical = true),
            CmdlineCheck("androidboot.vbmeta.device_state=unlocked", "vbmeta unlocked", isCritical = true),
            CmdlineCheck("skip_initramfs", "Skip initramfs (possible root)", isCritical = false),
            CmdlineCheck("init=/sbin", "Custom init path", isCritical = true),
            CmdlineCheck("init=/system", "Custom init path", isCritical = false),
            CmdlineCheck("androidboot.force_normal_boot=1", "Force normal boot", isCritical = false),
            CmdlineCheck("magisk", "Magisk reference in cmdline", isCritical = true),
            CmdlineCheck("ksu", "KernelSU reference in cmdline", isCritical = true),
            CmdlineCheck("apatch", "APatch reference in cmdline", isCritical = true),
            CmdlineCheck("rootfs=", "Custom rootfs", isCritical = false),
            CmdlineCheck("androidboot.slot_suffix=", "Slot suffix present", isCritical = false),
        )
    }
}

private data class KernelKeywordRule(
    val keyword: String,
    val ignoreCase: Boolean,
    val wholeWord: Boolean = false,
) {
    private val regex: Regex by lazy {
        Regex(
            pattern = if (wholeWord) {
                """\b${Regex.escape(keyword)}\b"""
            } else {
                Regex.escape(keyword)
            },
            options = listOfNotNull(
                RegexOption.IGNORE_CASE.takeIf { ignoreCase },
            ).toSet(),
        )
    }

    fun matches(
        input: String,
    ): Boolean = regex.containsMatchIn(input)
}

private data class CmdlineCheck(
    val pattern: String,
    val description: String,
    val isCritical: Boolean,
)

private data class CvePatchAssessment(
    val state: KernelCheckCvePatchState,
    val detail: String,
)

private data class UnicodeBypassProbe(
    val state: UnicodeBypassState,
    val bypassName: String,
    val detail: String? = null,
)

private data class DirectoryListProbe(
    val completed: Boolean,
    val exitCode: Int?,
) {
    val succeeded: Boolean
        get() = completed && exitCode == 0
}

private enum class UnicodeBypassState {
    BYPASSED,
    BLOCKED,
    INCONCLUSIVE,
}

private data class NonLatinScriptScanResult(
    val scriptNames: List<String>,
    val samples: List<String>,
)

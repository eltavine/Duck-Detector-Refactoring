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
import java.util.LinkedHashSet
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

        val dangerFindings = mutableListOf<KernelCheckFinding>()
        val infoFindings = mutableListOf<KernelCheckFinding>()
        val combinedIdentity = identitySources.joinToString(separator = "\n")

        val emojis = findEmojis(combinedIdentity)
        if (emojis.isNotEmpty()) {
            dangerFindings += KernelCheckFinding(
                id = "emoji",
                label = "Emoji markers",
                value = emojis.joinToString(" "),
                detail = "Kernel identity contains emoji codepoints.",
                severity = KernelCheckFindingSeverity.HARD,
            )
        }

        val chineseChars = findChineseCharacters(combinedIdentity)
        if (chineseChars.isNotEmpty()) {
            dangerFindings += KernelCheckFinding(
                id = "chinese_chars",
                label = "Chinese glyphs",
                value = chineseChars.joinToString(""),
                detail = "Kernel identity contains CJK characters.",
                severity = KernelCheckFindingSeverity.HARD,
            )
        }

        val nonLatinScriptResult = findNonLatinScriptCharacters(combinedIdentity)
        if (nonLatinScriptResult.samples.isNotEmpty()) {
            dangerFindings += KernelCheckFinding(
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

        val telegramMatches = TELEGRAM_REGEX.findAll(combinedIdentity)
            .map { it.value }
            .distinct()
            .toList()
        if (telegramMatches.isNotEmpty()) {
            dangerFindings += KernelCheckFinding(
                id = "telegram_ref",
                label = "Telegram reference",
                value = telegramMatches.joinToString(", "),
                detail = "Kernel identity references TG/Telegram style handles or channels.",
                severity = KernelCheckFindingSeverity.HARD,
            )
        }

        val mentionMatches = MENTION_REGEX.findAll(combinedIdentity)
            .map { it.value }
            .distinct()
            .toList()
        if (mentionMatches.isNotEmpty()) {
            dangerFindings += KernelCheckFinding(
                id = "at_mention",
                label = "@ mentions",
                value = mentionMatches.joinToString(", "),
                detail = "Kernel identity contains maintainer-style @ mentions.",
                severity = KernelCheckFindingSeverity.HARD,
            )
        }

        val customKeywords = detectCustomKernelKeywords(combinedIdentity)
        if (customKeywords.isNotEmpty()) {
            dangerFindings += KernelCheckFinding(
                id = "custom_kernel",
                label = "Custom identifiers",
                value = customKeywords.joinToString(", "),
                detail = "Known community kernel identifiers matched the kernel identity.",
                severity = KernelCheckFindingSeverity.HARD,
            )
        }

        val cmdlineMatches = nativeSnapshot.findings.details("CMDLINE|CRITICAL|")
            .ifEmpty { detectCriticalCmdlineFallback(procCmdline) }
        if (cmdlineMatches.isNotEmpty()) {
            dangerFindings += KernelCheckFinding(
                id = "suspicious_cmdline",
                label = "Boot cmdline",
                value = "${cmdlineMatches.size} hit(s)",
                detail = cmdlineMatches.joinToString(separator = "\n"),
                severity = KernelCheckFindingSeverity.HARD,
            )
        }

        val buildTimeDetail = nativeSnapshot.findings.firstDetail("BUILD_TIME|MISMATCH|")
            ?: detectBuildTimeMismatchFallback(
                unameOutput = unameOutput,
                procVersion = procVersion,
                systemBuildTime = Build.TIME,
            )
        if (buildTimeDetail != null) {
            dangerFindings += KernelCheckFinding(
                id = "build_time_mismatch",
                label = "Build time drift",
                value = "Mismatch",
                detail = buildTimeDetail,
                severity = KernelCheckFindingSeverity.HARD,
            )
        }

        val kptrDetail = nativeSnapshot.findings.firstDetail("KPTR_RESTRICT|DISABLED|")
        if (kptrDetail != null || nativeSnapshot.kptrExposed) {
            infoFindings += KernelCheckFinding(
                id = "kptr_exposed",
                label = "Kernel pointers",
                value = "Exposed",
                detail = kptrDetail ?: "kptr_restrict appears disabled.",
                severity = KernelCheckFindingSeverity.INFO,
            )
        }

        val cveAssessment = detectCvePatchState()
        if (cveAssessment.state == KernelCheckCvePatchState.UNPATCHED ||
            cveAssessment.state == KernelCheckCvePatchState.PARTIALLY_PATCHED
        ) {
            infoFindings += KernelCheckFinding(
                id = "cve_patch_state",
                label = "CVE-2024-43093",
                value = cveAssessment.state.label,
                detail = cveAssessment.detail,
                severity = KernelCheckFindingSeverity.INFO,
            )
        }

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
    ): List<String> {
        if (input.isBlank()) {
            return emptyList()
        }
        return buildList {
            CUSTOM_KERNEL_KEYWORDS.forEach { keyword ->
                if (input.contains(keyword, ignoreCase = true)) {
                    add(keyword)
                }
            }
            CASE_SENSITIVE_KEYWORDS.forEach { keyword ->
                if (input.contains(keyword)) {
                    add(keyword)
                }
            }
        }
    }

    private fun detectCriticalCmdlineFallback(
        procCmdline: String,
    ): List<String> {
        if (procCmdline.isBlank()) {
            return emptyList()
        }
        return CMDLINE_CHECKS.filter {
            it.isCritical && procCmdline.contains(
                it.pattern,
                ignoreCase = true
            )
        }
            .map { it.description }
    }

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
        for ((label, text) in sources) {
            if (text.isBlank()) {
                continue
            }
            val match = BUILD_TIME_REGEX.find(text) ?: continue
            val kernelDateText = match.value.replace(Regex("\\s+"), " ")
            val kernelDate = runCatching { parser.parse(kernelDateText) }.getOrNull() ?: continue
            val diffDays = TimeUnit.MILLISECONDS.toDays(kernelDate.time - systemBuildTime)
            if (diffDays <= 30 && diffDays >= -365) {
                continue
            }
            val systemDate = SimpleDateFormat("yyyy-MM-dd", Locale.US).format(Date(systemBuildTime))
            val kernelDateShort = SimpleDateFormat("yyyy-MM-dd", Locale.US).format(kernelDate)
            return "$label -> Kernel: $kernelDateShort, System: $systemDate (diff: $diffDays days)"
        }
        return null
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
    ): List<String> {
        val matches = LinkedHashSet<String>()
        var index = 0
        while (index < text.length) {
            val codePoint = text.codePointAt(index)
            if (isEmoji(codePoint)) {
                matches += String(Character.toChars(codePoint))
            }
            index += Character.charCount(codePoint)
        }
        return matches.toList()
    }

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
    ): List<String> {
        val matches = LinkedHashSet<String>()
        var index = 0
        while (index < text.length) {
            val codePoint = text.codePointAt(index)
            if (isChineseCharacter(codePoint)) {
                matches += String(Character.toChars(codePoint))
            }
            index += Character.charCount(codePoint)
        }
        return matches.toList()
    }

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
    ): NonLatinScriptScanResult {
        val scripts = LinkedHashSet<String>()
        val samples = LinkedHashSet<String>()
        var index = 0
        while (index < text.length) {
            val codePoint = text.codePointAt(index)
            if (isUnexpectedNonLatinScript(codePoint)) {
                scripts += unicodeScriptLabel(Character.UnicodeScript.of(codePoint))
                if (samples.size < MAX_SCRIPT_SAMPLE_COUNT) {
                    samples += String(Character.toChars(codePoint))
                }
            }
            index += Character.charCount(codePoint)
        }
        return NonLatinScriptScanResult(
            scriptNames = scripts.toList(),
            samples = samples.toList(),
        )
    }

    private fun isUnexpectedNonLatinScript(
        codePoint: Int,
    ): Boolean {
        if (!Character.isLetter(codePoint)) {
            return false
        }
        return when (Character.UnicodeScript.of(codePoint)) {
            Character.UnicodeScript.LATIN,
            Character.UnicodeScript.COMMON,
            Character.UnicodeScript.INHERITED,
            Character.UnicodeScript.HAN -> false

            else -> true
        }
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

        var hadCompletedAttempt = false
        bypassPaths.forEach { bypassPath ->
            val probe = runListProbe(bypassPath)
            if (probe.completed) {
                hadCompletedAttempt = true
            }
            if (probe.succeeded) {
                return UnicodeBypassProbe(
                    state = UnicodeBypassState.BYPASSED,
                    bypassName = bypassName,
                    detail = "$bypassName successfully bypassed the path filter.",
                )
            }
        }

        return if (hadCompletedAttempt) {
            UnicodeBypassProbe(
                state = UnicodeBypassState.BLOCKED,
                bypassName = bypassName,
                detail = "$bypassName was blocked by the path filter.",
            )
        } else {
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
            Regex("""\bTG\b|\btg\b|\bTelegram\b|\btelegram\b|t\.me/""", RegexOption.IGNORE_CASE)

        private val MENTION_REGEX = Regex("@[A-Za-z0-9_]+")

        private val BUILD_TIME_REGEX =
            Regex("""\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\w+\s+\d{4}""")

        private val CUSTOM_KERNEL_KEYWORDS = listOf(
            "xiaoxiaow",
            "qdykernel",
            "numbers",
            "cctv",
            "shirkneko",
            "mirinfork",
            "brokestar",
            "sukisu",
        )

        private val CASE_SENSITIVE_KEYWORDS = listOf("OKI")

        private val KEYWORD_SCAN_COUNT =
            CUSTOM_KERNEL_KEYWORDS.size + CASE_SENSITIVE_KEYWORDS.size + 5

        private val CMDLINE_CHECKS = listOf(
            CmdlineCheck(
                "androidboot.verifiedbootstate=orange",
                "Bootloader unlocked (orange)",
                true
            ),
            CmdlineCheck("androidboot.verifiedbootstate=yellow", "Self-signed boot (yellow)", true),
            CmdlineCheck("androidboot.enable_dm_verity=0", "dm-verity disabled", true),
            CmdlineCheck("androidboot.secboot=disabled", "Secure boot disabled", true),
            CmdlineCheck("androidboot.vbmeta.device_state=unlocked", "vbmeta unlocked", true),
            CmdlineCheck("skip_initramfs", "Skip initramfs (possible root)", false),
            CmdlineCheck("init=/sbin", "Custom init path", true),
            CmdlineCheck("init=/system", "Custom init path", false),
            CmdlineCheck("androidboot.force_normal_boot=1", "Force normal boot", false),
            CmdlineCheck("magisk", "Magisk reference in cmdline", true),
            CmdlineCheck("ksu", "KernelSU reference in cmdline", true),
            CmdlineCheck("apatch", "APatch reference in cmdline", true),
            CmdlineCheck("rootfs=", "Custom rootfs", false),
            CmdlineCheck("androidboot.slot_suffix=", "Slot suffix present", false),
        )
    }
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

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

package com.eltavine.duckdetector.features.memory.domain

enum class MemoryStage {
    LOADING,
    READY,
    FAILED,
}

enum class MemoryFindingSection {
    HOOK,
    MAPS,
    FD,
    SIGNAL,
    VDSO,
    LINKER,
}

enum class MemoryFindingSeverity(
    val label: String,
) {
    CRITICAL("Critical"),
    HIGH("High"),
    MEDIUM("Review"),
    LOW("Low"),
}

enum class MemoryMethodOutcome {
    CLEAN,
    REVIEW,
    DETECTED,
    SUPPORT,
}

data class MemoryFinding(
    val id: String,
    val section: MemoryFindingSection,
    val category: String,
    val label: String,
    val detail: String,
    val severity: MemoryFindingSeverity,
    val detailMonospace: Boolean,
)

/** The methods a memory scan reports, in report order; [label] is the key each method is listed under. */
enum class MemoryMethod(val label: String) {
    GOT_PLT_RESOLUTION("GOT/PLT resolution"),
    ENTRY_PROLOGUE("Entry prologue"),
    MAPS_SMAPS("maps + smaps"),
    FD_BACKED_CODE("FD-backed code"),
    SIGNAL_HANDLERS("Signal handlers"),
    LOADER_VISIBILITY("Loader visibility"),
}

data class MemoryMethodResult(
    val method: MemoryMethod,
    val summary: String,
    val outcome: MemoryMethodOutcome,
    val detail: String,
) {
    val label: String
        get() = method.label
}

data class MemoryReport(
    val stage: MemoryStage,
    val nativeAvailable: Boolean,
    val findings: List<MemoryFinding>,
    val methods: List<MemoryMethodResult>,
    val modifiedFunctionCount: Int,
    val gotPltHook: Boolean,
    val inlineHook: Boolean,
    val prologueModified: Boolean,
    val trampoline: Boolean,
    val suspiciousJump: Boolean,
    val writableExec: Boolean,
    val anonymousExec: Boolean,
    val systemAnonymousExec: Boolean,
    val systemCopyModified: Boolean,
    val systemCopyUnverified: Boolean,
    val swappedExec: Boolean,
    val sharedDirtyExec: Boolean,
    val deletedSo: Boolean,
    val suspiciousMemfd: Boolean,
    val execAshmem: Boolean,
    val devZeroExec: Boolean,
    val signalHandler: Boolean,
    val fridaSignal: Boolean,
    val anonymousSignal: Boolean,
    val vdsoRemapped: Boolean,
    val vdsoUnusualBase: Boolean,
    val deletedLibrary: Boolean,
    val hiddenModule: Boolean,
    val mapsOnlyModule: Boolean,
    val errorMessage: String? = null,
) {
    val dangerFindingCount: Int
        get() = findings.count { it.severity == MemoryFindingSeverity.CRITICAL || it.severity == MemoryFindingSeverity.HIGH }

    val reviewFindingCount: Int
        get() = findings.count { it.severity == MemoryFindingSeverity.MEDIUM }

    val lowFindingCount: Int
        get() = findings.count { it.severity == MemoryFindingSeverity.LOW }

    val hookFindingCount: Int
        get() = findings.count { it.section == MemoryFindingSection.HOOK }

    val mappingFindingCount: Int
        get() = findings.count { it.section == MemoryFindingSection.MAPS || it.section == MemoryFindingSection.FD }

    val loaderFindingCount: Int
        get() = findings.count { it.section == MemoryFindingSection.SIGNAL || it.section == MemoryFindingSection.VDSO || it.section == MemoryFindingSection.LINKER }

    companion object {
        fun loading(): MemoryReport {
            return MemoryReport(
                stage = MemoryStage.LOADING,
                nativeAvailable = true,
                findings = emptyList(),
                methods = emptyList(),
                modifiedFunctionCount = 0,
                gotPltHook = false,
                inlineHook = false,
                prologueModified = false,
                trampoline = false,
                suspiciousJump = false,
                writableExec = false,
                anonymousExec = false,
                systemAnonymousExec = false,
                systemCopyModified = false,
                systemCopyUnverified = false,
                swappedExec = false,
                sharedDirtyExec = false,
                deletedSo = false,
                suspiciousMemfd = false,
                execAshmem = false,
                devZeroExec = false,
                signalHandler = false,
                fridaSignal = false,
                anonymousSignal = false,
                vdsoRemapped = false,
                vdsoUnusualBase = false,
                deletedLibrary = false,
                hiddenModule = false,
                mapsOnlyModule = false,
            )
        }

        fun failed(message: String): MemoryReport {
            return loading().copy(
                stage = MemoryStage.FAILED,
                nativeAvailable = false,
                errorMessage = message,
            )
        }
    }
}

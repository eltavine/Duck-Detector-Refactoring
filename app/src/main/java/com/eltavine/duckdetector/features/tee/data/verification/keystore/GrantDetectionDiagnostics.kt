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

package com.eltavine.duckdetector.features.tee.data.verification.keystore

import java.security.UnrecoverableKeyException

internal class GrantDetectionDiagnosticLog(
    title: String,
) {
    private val lines = mutableListOf(title)

    fun add(stage: String, detail: String) {
        detail.takeIf { it.isNotBlank() }?.let { lines += "[$stage] $it" }
    }

    fun addRaw(text: String) {
        text.takeIf { it.isNotBlank() }?.let { lines += it }
    }

    fun addThrowable(stage: String, throwable: Throwable) {
        // UI detail intentionally receives only describe(throwable). The full stack stays in this
        // diagnostic payload, which is reachable through the existing hidden double-click copy path.
        // UI detail 只接收 describe(throwable)；完整堆栈仅保存在诊断 payload 中，通过既有隐藏双击复制入口获取。
        add(stage, GrantThrowableFormatter.describe(throwable))
        throwable.stackTraceToString()
            .trim()
            .takeIf { it.isNotBlank() }
            ?.let { lines += it }
    }

    fun text(): String = lines.joinToString(separator = "\n")
}

internal object GrantThrowableFormatter {
    fun describe(throwable: Throwable): String {
        val type = throwable.javaClass.simpleName.ifBlank { throwable.javaClass.name }
        val message = throwable.message?.takeIf { it.isNotBlank() }
        return if (message == null) type else "$type: $message"
    }

    fun isGrantAliasNotFound(throwable: Throwable): Boolean {
        // Keep both exception type and AOSP-style message strict so transient/OEM grant failures stay unavailable.
        // 严格限定异常类型和 AOSP 文案，避免把 OEM/暂态 grant 失败误归因为授权域断裂。
        return throwable is UnrecoverableKeyException &&
            throwable.message?.contains("No key found by the given alias", ignoreCase = true) == true
    }
}

internal fun appendGrantDetail(detail: String, extra: String): String {
    return when {
        detail.isBlank() -> extra
        extra.isBlank() -> detail
        else -> "$detail; $extra"
    }
}

internal fun combineGrantStageDetails(
    publicDetail: String,
    hiddenDetail: String?,
    privateDetail: String? = null,
): String {
    // Keep visible detail compact and stage-scoped. Full exception stacks stay in
    // GrantDetectionDiagnosticLog for hidden-copy diagnostics.
    // 可见 detail 保持紧凑并按阶段归档；完整异常堆栈保留在 GrantDetectionDiagnosticLog，供隐藏复制诊断使用。
    return buildList {
        add(formatGrantStageDetail("Public", publicDetail))
        hiddenDetail?.let { add(formatGrantStageDetail("Hidden", it)) }
        privateDetail?.let { add(formatGrantStageDetail("Private", it)) }
    }.joinToString(separator = " | ")
}

private fun formatGrantStageDetail(
    label: String,
    detail: String,
): String {
    val text = detail.ifBlank { "not executed" }
    return if (text.startsWith("$label:")) {
        text
    } else {
        "$label: $text"
    }
}

internal fun visibleGrantDetail(detail: String): String {
    // Isolated grantee failures may carry stack traces for hidden copy. Strip stack-frame lines before
    // composing visible card text so detector UI never renders raw exception traces.
    // isolated grantee 失败可能携带供隐藏复制使用的堆栈；拼接可见卡片文案前剥离 stack-frame 行，避免 UI 直接展示原始异常堆栈。
    return detail
        .lineSequence()
        .firstOrNull { line -> line.isNotBlank() && !line.trimStart().startsWith("at ") }
        ?.trim()
        .orEmpty()
}

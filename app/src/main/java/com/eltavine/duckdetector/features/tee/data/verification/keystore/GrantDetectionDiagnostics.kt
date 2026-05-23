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
    privateDetail: String?,
): String {
    return buildList {
        add("Public: ${publicDetail.ifBlank { "not executed" }}")
        privateDetail?.let { add("Private: ${it.ifBlank { "not executed" }}") }
    }.joinToString(separator = " • ")
}

internal fun visibleGrantDetail(detail: String): String {
    return detail
        .lineSequence()
        .firstOrNull { line -> line.isNotBlank() && !line.trimStart().startsWith("at ") }
        ?.trim()
        .orEmpty()
}

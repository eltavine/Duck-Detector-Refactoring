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

package com.eltavine.duckdetector.features.selinux.data.probes

object SelinuxProcAttrCurrentPayloadCodec {

    fun encode(result: SelinuxProcAttrCurrentResult): String {
        return listOf(
            result.label,
            result.targetContext,
            result.outcomeClass,
            result.rawMessage,
        ).joinToString(FIELD_SEPARATOR)
    }

    fun decode(payload: String): SelinuxProcAttrCurrentResult? {
        val parts = payload.split(FIELD_SEPARATOR, limit = 4)
        if (parts.size != 4) {
            return null
        }
        return SelinuxProcAttrCurrentResult(
            label = parts[0],
            targetContext = parts[1],
            outcomeClass = parts[2],
            rawMessage = parts[3],
        )
    }

    private const val FIELD_SEPARATOR = "\t"
}

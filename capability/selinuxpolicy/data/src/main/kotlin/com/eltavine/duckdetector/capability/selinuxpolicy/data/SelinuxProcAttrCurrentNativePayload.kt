// SPDX-License-Identifier: Apache-2.0
package com.eltavine.duckdetector.capability.selinuxpolicy.data

/** Native controls use the existing four-column result protocol, including the retained raw errors. */
internal object SelinuxProcAttrCurrentNativePayload {
    fun decode(raw: String): List<SelinuxProcAttrCurrentResult> {
        require(raw.length <= 32_768) { "Oversized context-write payload" }
        val lines = raw.lineSequence().filter(String::isNotEmpty).toList()
        require(lines.firstOrNull() == "SCHEMA=1") { "Unsupported context-write schema" }
        val results = lines.drop(1).map { line ->
            require(line.startsWith("RESULT=")) { "Unexpected context-write record" }
            requireNotNull(SelinuxProcAttrCurrentPayloadCodec.decode(line.removePrefix("RESULT=")))
        }
        require(results.size in 1..10 && results.map { it.label }.distinct().size == results.size)
        val control = results.first()
        require(control.label == SelinuxProcAttrCurrentResult.CONTROL_LABEL && control.targetContext.isEmpty())
        val states = setOf("UNSUPPORTED", "PERMISSION_LIMITED", "UNAVAILABLE", "INCONCLUSIVE",
            SelinuxProcAttrCurrentResult.OUTCOME_CONTROLS_PASSED)
        require(control.outcomeClass in states)
        results.drop(1).forEach { result ->
            require(result.targetContext.isNotBlank())
            require(result.outcomeClass in setOf("INCONCLUSIVE",
                SelinuxProcAttrCurrentResult.OUTCOME_CONTEXT_RECOGNIZED,
                SelinuxProcAttrCurrentResult.OUTCOME_NORMAL_EINVAL))
        }
        if (control.outcomeClass == SelinuxProcAttrCurrentResult.OUTCOME_CONTROLS_PASSED) {
            require(results.size == 10) { "Incomplete controlled context-write results" }
        } else {
            require(results.drop(1).all { it.outcomeClass == "INCONCLUSIVE" })
        }
        return results
    }
}

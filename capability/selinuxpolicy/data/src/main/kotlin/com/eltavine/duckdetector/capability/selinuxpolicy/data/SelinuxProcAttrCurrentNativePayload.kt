// SPDX-License-Identifier: Apache-2.0
package com.eltavine.duckdetector.capability.selinuxpolicy.data

/** Native controls use the existing four-column result protocol, including the retained raw errors. */
internal object SelinuxProcAttrCurrentNativePayload {
    private val CONTROL_STATES = setOf(
        SelinuxProcAttrCurrentResult.OUTCOME_CONTROLS_PASSED,
        SelinuxProcAttrCurrentResult.OUTCOME_PERMISSION_LIMITED,
        SelinuxProcAttrCurrentResult.OUTCOME_UNSUPPORTED,
        SelinuxProcAttrCurrentResult.OUTCOME_UNAVAILABLE,
        SelinuxProcAttrCurrentResult.OUTCOME_INCONCLUSIVE,
    )
    private val TARGET_STATES = setOf(
        SelinuxProcAttrCurrentResult.OUTCOME_CONTEXT_RECOGNIZED,
        SelinuxProcAttrCurrentResult.OUTCOME_NORMAL_EINVAL,
        SelinuxProcAttrCurrentResult.OUTCOME_INCONCLUSIVE,
    )

    fun decode(raw: String): List<SelinuxProcAttrCurrentResult> {
        require(raw.length <= 32_768) { "Oversized context-write payload" }
        val lines = raw.lineSequence().filter(String::isNotEmpty).toList()
        require(lines.firstOrNull() == "SCHEMA=1") { "Unsupported context-write schema" }
        val results = lines.drop(1).map { line ->
            require(line.startsWith("RESULT=")) { "Unexpected context-write record" }
            requireNotNull(SelinuxProcAttrCurrentPayloadCodec.decode(line.removePrefix("RESULT=")))
        }
        val recordLimit = SelinuxProcAttrCurrentResult.TARGET_COUNT + 1
        require(results.size in 1..recordLimit && results.map { it.label }.distinct().size == results.size)
        val control = results.first()
        require(control.label == SelinuxProcAttrCurrentResult.CONTROL_LABEL && control.targetContext.isEmpty())
        require(control.outcomeClass in CONTROL_STATES)
        results.drop(1).forEach { result ->
            require(result.targetContext.isNotBlank())
            require(result.outcomeClass in TARGET_STATES)
        }
        if (control.outcomeClass == SelinuxProcAttrCurrentResult.OUTCOME_CONTROLS_PASSED) {
            require(results.size == recordLimit) { "Incomplete controlled context-write results" }
        } else {
            require(results.drop(1).all { it.outcomeClass == SelinuxProcAttrCurrentResult.OUTCOME_INCONCLUSIVE })
        }
        return results
    }
}

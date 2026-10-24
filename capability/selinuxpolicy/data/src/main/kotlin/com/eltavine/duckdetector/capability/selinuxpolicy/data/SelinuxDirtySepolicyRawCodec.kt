package com.eltavine.duckdetector.capability.selinuxpolicy.data

import com.eltavine.duckdetector.core.native.NativePayloadCodec

internal object SelinuxDirtySepolicyRawCodec {
    fun encode(snapshot: SelinuxDirtySepolicyRawSnapshot): String = buildString {
        append(snapshot.state.name).append('\n')
        append(NativePayloadCodec.encodeValue(snapshot.failedQuery.orEmpty())).append('\n')
        append(NativePayloadCodec.encodeValue(snapshot.rawResponse.orEmpty())).append('\n')
        append(NativePayloadCodec.encodeValue(snapshot.failureReason.orEmpty())).append('\n')
        append(if (snapshot.controlsPassed) '1' else '0').append('\n')
        append(if (snapshot.stable) '1' else '0').append('\n')
        snapshot.observations.forEach { observation ->
            append(listOf(observation.query, observation.outcome, observation.response.orEmpty(), observation.reason.orEmpty(),
                observation.stage.orEmpty(), observation.bytesRead?.toString().orEmpty(), observation.errno?.toString().orEmpty())
                .joinToString("\t") { NativePayloadCodec.encodeValue(it) })
            append('\n')
        }
        snapshot.contextChecks.forEach { observation ->
            append("CONTEXT\t")
            append(listOf(observation.context, observation.contextNode, observation.accessNode, observation.attrCurrent,
                observation.verdict, observation.verifiedBy.name)
                .joinToString("\t") { NativePayloadCodec.encodeValue(it) })
            append('\n')
        }
        snapshot.avdSeqno?.let { append("AVD_SEQNO\t").append(it).append('\n') }
        snapshot.allowedRules.forEach { append("ALLOW\t").append(NativePayloadCodec.encodeValue(it)).append('\n') }
        snapshot.apiDisagreements.forEach { append("DIFF\t").append(NativePayloadCodec.encodeValue(it)).append('\n') }
        append("CTX_CONTROLS\t").append(if (snapshot.contextControlsPassed) '1' else '0').append('\n')
        snapshot.recognizedContexts.forEach { append("CTX_HIT\t").append(NativePayloadCodec.encodeValue(it)).append('\n') }
        append("CLASS0_CONTROLS\t").append(if (snapshot.classZeroControlsPassed) '1' else '0').append('\n')
        snapshot.warningRules.forEach { append("WARN_RULE\t").append(NativePayloadCodec.encodeValue(it)).append('\n') }
        snapshot.statusEpoch?.let { append("STATUS_EPOCH\t").append(NativePayloadCodec.encodeValue(it)).append('\n') }
        snapshot.statusWarnings.forEach { append("STATUS_WARN\t").append(NativePayloadCodec.encodeValue(it)).append('\n') }
        append("EPOCH_DEVIATION\t").append(if (snapshot.epochDeviation) '1' else '0').append('\n')
        append("PERMISSIVE_FLAGS\t").append(if (snapshot.permissiveDecisionSeen) '1' else '0').append('\n')
        append("CONTEXT_COLLECTION\t").append(snapshot.contextCollection.name).append('\n')
        append("COMPAT_VERDICT\t").append(snapshot.compatibility.verdict.name).append('\n')
        snapshot.compatibility.reasons.forEach {
            append("COMPAT_REASON\t").append(NativePayloadCodec.encodeValue(it)).append('\n')
        }
    }

    fun decode(raw: String): SelinuxDirtySepolicyRawSnapshot {
        val lines = raw.lines()
        if (lines.size < 6) return SelinuxDirtySepolicyRawSnapshot()
        return SelinuxDirtySepolicyRawSnapshot(
            state = SelinuxDirtySepolicyRawState.entries.firstOrNull { it.name == lines[0] }
                ?: SelinuxDirtySepolicyRawState.NOT_COLLECTED,
            failedQuery = NativePayloadCodec.decodeValue(lines[1]).ifEmpty { null },
            rawResponse = NativePayloadCodec.decodeValue(lines[2]).ifEmpty { null },
            failureReason = NativePayloadCodec.decodeValue(lines[3]).ifEmpty { null },
            controlsPassed = lines[4] == "1",
            stable = lines[5] == "1",
            observations = lines.drop(6).filterNot {
                it.startsWith("CONTEXT\t") || it.startsWith("AVD_SEQNO\t") ||
                    it.startsWith("ALLOW\t") || it.startsWith("DIFF\t") ||
                    it.startsWith("CTX_CONTROLS\t") || it.startsWith("CTX_HIT\t") ||
                    it.startsWith("CLASS0_CONTROLS\t") || it.startsWith("WARN_RULE\t") ||
                    it.startsWith("STATUS_EPOCH\t") || it.startsWith("STATUS_WARN\t") ||
                    it.startsWith("EPOCH_DEVIATION\t") || it.startsWith("PERMISSIVE_FLAGS\t") ||
                    it.startsWith("CONTEXT_COLLECTION\t") || it.startsWith("COMPAT_VERDICT\t") ||
                    it.startsWith("COMPAT_REASON\t")
            }
                .mapNotNull { line ->
                val fields = line.split('\t')
                if (fields.size != 4 && fields.size != 7) null else SelinuxRawAccessObservation(
                    query = NativePayloadCodec.decodeValue(fields[0]),
                    outcome = NativePayloadCodec.decodeValue(fields[1]),
                    response = NativePayloadCodec.decodeValue(fields[2]).ifEmpty { null },
                    reason = NativePayloadCodec.decodeValue(fields[3]).ifEmpty { null },
                    stage = fields.getOrNull(4)?.let(NativePayloadCodec::decodeValue)?.ifEmpty { null },
                    bytesRead = fields.getOrNull(5)?.toIntOrNull(),
                    errno = fields.getOrNull(6)?.toIntOrNull(),
                )
            },
            contextChecks = lines.drop(6).filter { it.startsWith("CONTEXT\t") }.mapNotNull { line ->
                val fields = line.split('\t')
                if (fields.size != 6 && fields.size != 7) null else SelinuxRawContextObservation(
                    context = NativePayloadCodec.decodeValue(fields[1]),
                    contextNode = NativePayloadCodec.decodeValue(fields[2]),
                    accessNode = NativePayloadCodec.decodeValue(fields[3]),
                    attrCurrent = NativePayloadCodec.decodeValue(fields[4]),
                    verdict = NativePayloadCodec.decodeValue(fields[5]),
                    verifiedBy = fields.getOrNull(6)?.let(NativePayloadCodec::decodeValue)?.let { name ->
                        SelinuxRawContextSource.entries.firstOrNull { it.name == name }
                    } ?: SelinuxRawContextSource.NONE,
                )
            },
            contextCollection = lines.firstOrNull { it.startsWith("CONTEXT_COLLECTION\t") }
                ?.substringAfter('\t')?.let { name ->
                    SelinuxRawContextCollectionState.entries.firstOrNull { it.name == name }
                } ?: SelinuxRawContextCollectionState.NOT_COLLECTED,
            avdSeqno = lines.firstOrNull { it.startsWith("AVD_SEQNO\t") }
                ?.substringAfter('\t')?.toLongOrNull(),
            allowedRules = lines.filter { it.startsWith("ALLOW\t") }
                .map { NativePayloadCodec.decodeValue(it.substringAfter('\t')) },
            apiDisagreements = lines.filter { it.startsWith("DIFF\t") }
                .map { NativePayloadCodec.decodeValue(it.substringAfter('\t')) },
            contextControlsPassed = lines.any { it == "CTX_CONTROLS\t1" },
            recognizedContexts = lines.filter { it.startsWith("CTX_HIT\t") }
                .map { NativePayloadCodec.decodeValue(it.substringAfter('\t')) },
            classZeroControlsPassed = lines.any { it == "CLASS0_CONTROLS\t1" },
            warningRules = lines.filter { it.startsWith("WARN_RULE\t") }
                .map { NativePayloadCodec.decodeValue(it.substringAfter('\t')) },
            statusEpoch = lines.firstOrNull { it.startsWith("STATUS_EPOCH\t") }
                ?.substringAfter('\t')?.let(NativePayloadCodec::decodeValue),
            statusWarnings = lines.filter { it.startsWith("STATUS_WARN\t") }
                .map { NativePayloadCodec.decodeValue(it.substringAfter('\t')) },
            epochDeviation = lines.any { it == "EPOCH_DEVIATION\t1" },
            permissiveDecisionSeen = lines.any { it == "PERMISSIVE_FLAGS\t1" },
            compatibility = SelinuxDirtySepolicyCompatibilityResult(
                verdict = lines.firstOrNull { it.startsWith("COMPAT_VERDICT\t") }
                    ?.substringAfter('\t')?.let { name ->
                        SelinuxDirtySepolicyCompatibilityVerdict.entries.firstOrNull { it.name == name }
                    } ?: SelinuxDirtySepolicyCompatibilityVerdict.NOT_COLLECTED,
                reasons = lines.filter { it.startsWith("COMPAT_REASON\t") }
                    .map { NativePayloadCodec.decodeValue(it.substringAfter('\t')) },
            ),
        )
    }
}

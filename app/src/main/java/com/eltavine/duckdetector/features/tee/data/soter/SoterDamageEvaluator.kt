package com.eltavine.duckdetector.features.tee.data.soter

import com.eltavine.duckdetector.features.tee.domain.TeeSoterState

class SoterDamageEvaluator {

    fun evaluate(
        serviceReachable: Boolean,
        keyPrepared: Boolean,
        signSessionAvailable: Boolean,
        errorMessage: String?,
    ): TeeSoterState {
        val available = serviceReachable && keyPrepared && signSessionAvailable
        val warning = serviceReachable && !available
        val summary = when {
            available -> "Soter Treble service was reachable and ASK/AuthKey/initSigh all succeeded."
            !serviceReachable -> errorMessage ?: "Soter Treble service was not reachable; probe skipped."
            errorMessage != null -> errorMessage
            !keyPrepared -> "Soter Treble service was reachable, but ASK/AuthKey preparation failed."
            else -> "Soter Treble service was reachable, but signing session initialization failed."
        }
        return TeeSoterState(
            serviceReachable = serviceReachable,
            keyPrepared = keyPrepared,
            signSessionAvailable = signSessionAvailable,
            available = available,
            warning = warning,
            summary = summary,
        )
    }
}

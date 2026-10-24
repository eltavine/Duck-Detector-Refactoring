package com.eltavine.duckdetector.features.selinux.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.selinux.domain.*

internal fun methodStatus(result: SelinuxCheckResult): DetectorStatus {
    if (result.dirtySepolicyWarningOnly) {
        return when {
            result.isSecure == false && result.dirtyPolicyTrusted -> DetectorStatus.warning()
            result.isSecure == true -> DetectorStatus.allClear()
            else -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }
    if (result.oracle == SelinuxOracle.DIRTY_SEPOLICY_RAW) {
        return when {
            result.dirtySepolicyDanger -> DetectorStatus.danger()
            result.isSecure == false -> DetectorStatus.warning()
            else -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }
    if (result.oracle == SelinuxOracle.ATTR_CURRENT_TIMING) {
        return if (result.isSecure == false) DetectorStatus.danger()
        else DetectorStatus.info(InfoKind.SUPPORT)
    }
    if (result.oracle == SelinuxOracle.CONTEXT_VALIDITY) {
        return when (result.contextValidity?.verdict) {
            SelinuxContextValidityVerdict.KSU_PRESENT -> DetectorStatus.danger()
            SelinuxContextValidityVerdict.CLEAN -> DetectorStatus.allClear()
            SelinuxContextValidityVerdict.AMBIGUOUS -> DetectorStatus.warning()
            SelinuxContextValidityVerdict.SELF_TEST_FAILED -> DetectorStatus.warning()
            SelinuxContextValidityVerdict.UNSUPPORTED,
            null -> when (contextValiditySupportState(result)) {
                AppZygoteCarrierSupportState.UNTRUSTED -> DetectorStatus.warning()
                AppZygoteCarrierSupportState.FAILED -> DetectorStatus.warning()
                AppZygoteCarrierSupportState.AVAILABLE -> DetectorStatus.info(InfoKind.SUPPORT)
            }
        }
    }
    if (result.oracle == SelinuxOracle.PROC_ATTR_CURRENT_WRITE) {
        return when {
            result.isSecure == false -> DetectorStatus.warning()
            else -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }
    if (result.oracle == SelinuxOracle.POLICYLOAD_SEQNO) {
        return when {
            result.isSecure == false -> DetectorStatus.danger()
            result.isSecure == true -> DetectorStatus.allClear()
            else -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }
    if (result.oracle == SelinuxOracle.STATUS_MMAP_ABI) {
        return when {
            result.isSecure == false -> DetectorStatus.danger()
            // "No violation observed" states what the requests saw; it does not exclude a handler
            // that keeps the upstream checks, so it stays clear without claiming one is absent.
            result.statusAbi?.verdict == SelinuxStatusAbiVerdict.NO_VIOLATION -> DetectorStatus.allClear()
            else -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }
    return when {
        result.permissionDenied -> DetectorStatus.allClear()
        result.isSecure == true -> DetectorStatus.allClear()
        result.isSecure == false -> DetectorStatus.danger()
        else -> DetectorStatus.info(InfoKind.SUPPORT)
    }
}

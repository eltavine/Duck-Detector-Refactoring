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

package com.eltavine.duckdetector.features.mount.domain

enum class MountZygoteNextState {
    PENDING,
    UNSUPPORTED,
    UNAVAILABLE,
    READY,
}

enum class MountZygoteNextNamespaceAssessment {
    LIKELY_INIT,
    PRIVATE_ANOMALY,
    INCONSISTENT,
    UNVERIFIED,
}

enum class MountZygoteNextExposure {
    NONE,
    ROOT_MOUNT_EXPOSURE,
}

data class MountZygoteNextMarker(
    val labels: List<String>,
    val mountPoint: String,
    val mountRoot: String,
    val fileSystemType: String,
    val source: String,
    val rawLine: String,
) {
    val dangerous: Boolean
        get() = labels.any { it != DEBUG_RAMDISK_LABEL }

    companion object {
        private const val DEBUG_RAMDISK_LABEL = "debug_ramdisk"
    }
}

data class MountZygoteNextReport(
    val state: MountZygoteNextState,
    val sdkInt: Int,
    val mainNamespaceInode: Long = 0L,
    val mainUid: Int = 0,
    val mainPropagation: String = "",
    val mainRootMountId: Long = 0L,
    val mainMinimumMountId: Long = 0L,
    val mainMaximumMountId: Long = 0L,
    val mainMountCount: Int = 0,
    val mainMountIdsByPoint: Map<String, Long> = emptyMap(),
    val mainMarkers: List<MountZygoteNextMarker> = emptyList(),
    val isolatedNamespaceInode: Long = 0L,
    val isolatedParentPid: Int = 0,
    val isolatedUid: Int = 0,
    val isolatedPropagation: String = "",
    val isolatedRootMountId: Long = 0L,
    val isolatedMinimumMountId: Long = 0L,
    val isolatedMaximumMountId: Long = 0L,
    val isolatedMountCount: Int = 0,
    val isolatedMountIdsByPoint: Map<String, Long> = emptyMap(),
    val isolatedMarkers: List<MountZygoteNextMarker> = emptyList(),
    val errorDetail: String = "",
) {
    val dangerousMarkers: List<MountZygoteNextMarker>
        get() = isolatedMarkers.filter(MountZygoteNextMarker::dangerous)

    val leakDetected: Boolean
        get() = state == MountZygoteNextState.READY && dangerousMarkers.isNotEmpty()

    val exposure: MountZygoteNextExposure
        get() = if (leakDetected) {
            MountZygoteNextExposure.ROOT_MOUNT_EXPOSURE
        } else {
            MountZygoteNextExposure.NONE
        }

    /**
     * Describes similarity to the reference launch layout, not namespace ancestry or root.
     * Mount IDs are reusable allocation identifiers rather than timestamps. A relative ID
     * ordering can neither prove nor contradict init lineage; layout differences remain
     * informational and direct root-managed records are evaluated independently.
     */
    val namespaceAssessment: MountZygoteNextNamespaceAssessment
        get() {
            if (state != MountZygoteNextState.READY) {
                return MountZygoteNextNamespaceAssessment.UNVERIFIED
            }
            if (!isolatedRouteValidated) {
                return MountZygoteNextNamespaceAssessment.UNVERIFIED
            }
            if (!mountEvidenceAvailable) {
                return MountZygoteNextNamespaceAssessment.UNVERIFIED
            }
            if (propagationContradictsInitSignature) {
                return MountZygoteNextNamespaceAssessment.INCONSISTENT
            }
            if (isolatedRootIsPrivate) {
                return MountZygoteNextNamespaceAssessment.PRIVATE_ANOMALY
            }
            if (namespaceSeparated && propagationMatchesAosp && mountIdOrderingMatchesAosp) {
                return MountZygoteNextNamespaceAssessment.LIKELY_INIT
            }
            return MountZygoteNextNamespaceAssessment.UNVERIFIED
        }

    val hasInitNamespaceCoverage: Boolean
        get() = namespaceAssessment == MountZygoteNextNamespaceAssessment.LIKELY_INIT

    val isolatedRouteValidated: Boolean
        get() = isolatedUid.isIsolatedUid()

    val namespaceAssessmentDetail: String
        get() {
            when (namespaceAssessment) {
                MountZygoteNextNamespaceAssessment.LIKELY_INIT -> return "The native view matches AOSP's init-managed default namespace: " +
                    "it is distinct from the classic app namespace, its root is shared and " +
                    "non-slave, the classic root is slave, and at least two thirds of three or " +
                    "more common anchor IDs plus its root/minimum IDs are older. This is a " +
                    "likely signature, not proof of namespace lineage."

                MountZygoteNextNamespaceAssessment.PRIVATE_ANOMALY -> return "The native isolated route has a private/slave root. Namespace policy can vary by build; this alone does not establish root or hiding."

                MountZygoteNextNamespaceAssessment.INCONSISTENT -> return "Propagation or relative reusable mount IDs differ from the reference signature. This does not establish an integrity violation or namespace ancestry."

                MountZygoteNextNamespaceAssessment.UNVERIFIED -> Unit
            }
            if (!isolatedRouteValidated) {
                return "The native isolated route or isolated UID could not be validated."
            }
            val reasons = buildList {
                if (!namespaceSeparated) add("namespace identities are missing or equal")
                if (!isolatedRootIsSharedNonSlave) {
                    add("native root is not shared and non-slave")
                }
                if (!mainRootIsSlaveNonShared) {
                    add("classic app root is not slave and non-shared")
                }
                if (!mountRecordCountsSufficient) {
                    add("mountinfo record count is too small for a namespace comparison")
                }
                if (anchorPairs.size < MIN_ANCHOR_PAIRS) {
                    add("fewer than $MIN_ANCHOR_PAIRS common anchor mount IDs")
                } else if (!anchorChronologySupported) {
                    add("native root/minimum/anchor mount IDs are not older than the classic app IDs")
                }
            }
            return "Init-managed namespace coverage is unverified" +
                if (reasons.isEmpty()) "." else ": ${reasons.joinToString()}."
        }

    val contrastObserved: Boolean
        get() = hasInitNamespaceCoverage

    private val namespaceSeparated: Boolean
        get() = mainNamespaceInode > 0L && isolatedNamespaceInode > 0L &&
            mainNamespaceInode != isolatedNamespaceInode

    private val propagationMatchesAosp: Boolean
        get() = isolatedRootIsSharedNonSlave && mainRootIsSlaveNonShared

    private val mountEvidenceAvailable: Boolean
        get() = mainRootMountId > 0L && isolatedRootMountId > 0L &&
            mainMinimumMountId > 0L && isolatedMinimumMountId > 0L &&
            mountRecordCountsSufficient

    private val mountRecordCountsSufficient: Boolean
        get() = mainMountCount >= MIN_MOUNT_RECORDS &&
            isolatedMountCount >= MIN_MOUNT_RECORDS

    private val propagationContradictsInitSignature: Boolean
        get() = propagationFields(mainPropagation).hasSharedAndMaster() ||
            propagationFields(isolatedPropagation).hasSharedAndMaster()

    private val isolatedRootIsSharedNonSlave: Boolean
        get() {
            val fields = propagationFields(isolatedPropagation)
            return fields.any { it.startsWith("shared:") } &&
                fields.none { it.startsWith("master:") }
        }

    private val mainRootIsSlaveNonShared: Boolean
        get() {
            val fields = propagationFields(mainPropagation)
            return fields.any { it.startsWith("master:") } &&
                fields.none { it.startsWith("shared:") }
        }

    private val mountIdOrderingMatchesAosp: Boolean
        get() = isolatedRootMountId > 0L && mainRootMountId > isolatedRootMountId &&
            isolatedMinimumMountId > 0L && mainMinimumMountId > isolatedMinimumMountId &&
            anchorChronologySupported

    private val anchorPairs: Set<String>
        get() = mainMountIdsByPoint.keys.intersect(isolatedMountIdsByPoint.keys)

    private val olderAnchorCount: Int
        get() = anchorPairs.count { point ->
            isolatedMountIdsByPoint.getValue(point) < mainMountIdsByPoint.getValue(point)
        }

    private val anchorChronologySupported: Boolean
        get() = anchorPairs.size >= MIN_ANCHOR_PAIRS && olderAnchorCount * 3 >= anchorPairs.size * 2

    private val isolatedRootIsPrivate: Boolean
        get() = isolatedRootMountId > 0L &&
            propagationFields(isolatedPropagation).none { it.startsWith("shared:") }

    private fun Int.isIsolatedUid(): Boolean {
        val appId = this % 100_000
        return appId in 90_000..99_999
    }

    private fun propagationFields(value: String): List<String> {
        return value.split(' ').filter(String::isNotBlank)
    }

    private fun List<String>.hasSharedAndMaster(): Boolean {
        return any { it.startsWith("shared:") } && any { it.startsWith("master:") }
    }

    companion object {
        private const val MIN_ANCHOR_PAIRS = 3
        private const val MIN_MOUNT_RECORDS = 8

        fun pending(): MountZygoteNextReport {
            return MountZygoteNextReport(
                state = MountZygoteNextState.PENDING,
                sdkInt = 0,
            )
        }
    }
}

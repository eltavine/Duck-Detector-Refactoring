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

package com.eltavine.duckdetector.capability.selinuxpolicy.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxCarrierProvenanceTest {
    private val origin = SelinuxCarrierProvenance(
        preloadPid = 23823,
        appUid = 10397,
        startedNanos = 42_000_000L,
        apkPath = "/data/app/old/base.apk",
        splitPaths = listOf("/data/app/old/split_config.arm64_v8a.apk"),
    )
    private val current = SelinuxCarrierExpectedCode(
        appUid = 10397,
        apkPath = origin.apkPath,
        splitPaths = origin.splitPaths,
        parentPid = origin.preloadPid,
    )

    @Test fun `preload evidence retains its parent and code origin across the payload wire format`() {
        val encoded = SelinuxCarrierProvenanceCodec.attach("AVAILABLE=1\n", origin)
        assertEquals(origin, SelinuxCarrierProvenanceCodec.read(encoded))
        assertTrue(encoded.endsWith("AVAILABLE=1\n"))
        assertNull(SelinuxCarrierProvenanceCodec.mismatch(origin, current, 50_000_000L))
    }

    @Test fun `carrier parent PID is transported even when preload payload is missing`() {
        val failure = SelinuxContextValidityCarrierService.carrierFailurePayload(
            SelinuxContextValidityCarrierService.PRELOAD_PAYLOAD_UNAVAILABLE, "Not inherited",
        )
        val wrapped = SelinuxCarrierProvenanceCodec.attachCarrierParent(failure, 23823)
        assertEquals(23823, SelinuxCarrierProvenanceCodec.carrierParentPid(wrapped))
        assertEquals(SelinuxContextValidityCarrierService.PRELOAD_PAYLOAD_UNAVAILABLE,
            SelinuxContextValidityBridge().parse(wrapped).failureReason)
        assertEquals(null, SelinuxCarrierProvenanceCodec.read(wrapped))
    }

    @Test fun `carrier parent PID is transported without breaking valid preload provenance`() {
        val raw = SelinuxCarrierProvenanceCodec.attach("AVAILABLE=1\n", origin)
        val wrapped = SelinuxCarrierProvenanceCodec.attachCarrierParent(raw, 23823)
        assertEquals(origin, SelinuxCarrierProvenanceCodec.read(wrapped))
        assertEquals(23823, SelinuxCarrierProvenanceCodec.carrierParentPid(wrapped))
        assertEquals(null, SelinuxCarrierProvenanceCodec.carrierParentPid(
            wrapped + "DUCK_CARRIER_PARENT_PID=23824\n"))
    }

    @Test fun `existing parent can be legitimately reused for the same APK without a new preload`() {
        assertNull(SelinuxCarrierProvenanceCodec.mismatch(origin, current, 9_000_000_000L))
    }

    @Test fun `same parent pid cannot validate a previous APK generation`() {
        assertEquals("App Zygote preload APK generation mismatch.", SelinuxCarrierProvenanceCodec.mismatch(
            origin, current.copy(apkPath = "/data/app/new/base.apk"), 50_000_000L,
        ))
    }

    @Test fun `a genuinely new parent with fresh preload data is accepted after update`() {
        val newer = origin.copy(preloadPid = 24404, apkPath = "/data/app/new/base.apk", startedNanos = 99_000_000L)
        val code = current.copy(apkPath = newer.apkPath, parentPid = newer.preloadPid)
        assertNull(SelinuxCarrierProvenanceCodec.mismatch(newer, code, 100_000_000L))
    }

    @Test fun `new parent pid cannot inherit a previous parent's preload`() {
        assertEquals("App Zygote preload parent PID mismatch.", SelinuxCarrierProvenanceCodec.mismatch(
            origin, current.copy(parentPid = 24499), 50_000_000L,
        ))
    }

    @Test fun `split APK and UID changes are rejected`() {
        assertEquals("App Zygote preload APK generation mismatch.", SelinuxCarrierProvenanceCodec.mismatch(
            origin, current.copy(splitPaths = emptyList()), 50_000_000L,
        ))
        assertEquals("App Zygote preload UID mismatch.", SelinuxCarrierProvenanceCodec.mismatch(
            origin, current.copy(appUid = 90001), 50_000_000L,
        ))
    }

    @Test fun `version code schema and build revision mismatches are rejected`() {
        val builtOrigin = origin.copy(versionCode = 321L, buildRevision = "abc123")
        val builtCurrent = current.copy(versionCode = 321L, buildRevision = "abc123")
        assertNull(SelinuxCarrierProvenanceCodec.mismatch(builtOrigin, builtCurrent, 50_000_000L))
        assertEquals("App Zygote preload version code mismatch.", SelinuxCarrierProvenanceCodec.mismatch(
            builtOrigin, builtCurrent.copy(versionCode = 322L), 50_000_000L,
        ))
        assertEquals("App Zygote preload schema mismatch.", SelinuxCarrierProvenanceCodec.mismatch(
            builtOrigin, builtCurrent.copy(payloadSchemaVersion = 2), 50_000_000L,
        ))
        assertEquals("App Zygote preload build revision mismatch.", SelinuxCarrierProvenanceCodec.mismatch(
            builtOrigin, builtCurrent.copy(buildRevision = "def456"), 50_000_000L,
        ))
    }

    @Test fun `missing corrupted and future-dated origins are not trusted`() {
        assertEquals("App Zygote preload provenance unavailable.", SelinuxCarrierProvenanceCodec.mismatch(
            null, current, 50_000_000L,
        ))
        assertEquals("App Zygote preload timestamp invalid.", SelinuxCarrierProvenanceCodec.mismatch(
            origin, current, 40_000_000L,
        ))
        assertNull(SelinuxCarrierProvenanceCodec.read("AVAILABLE=1\n"))
        assertNull(SelinuxCarrierProvenanceCodec.read(
            SelinuxCarrierProvenanceCodec.attach("AVAILABLE=1\n", origin)
                .replace("DUCK_PRELOAD_PID=23823\n", "DUCK_PRELOAD_PID=23823\nDUCK_PRELOAD_PID=23823\n"),
        ))
    }

    @Test fun `escaped APK names preserve provenance encoding`() {
        val unusual = origin.copy(apkPath = "/data/app/path\\name/line\nbase.apk")
        val encoded = SelinuxCarrierProvenanceCodec.attach("AVAILABLE=1\n", unusual)
        assertEquals(unusual, SelinuxCarrierProvenanceCodec.read(encoded))
    }

    @Test fun `service accepts matching preload and preserves known missing-payload failure`() {
        val raw = SelinuxCarrierProvenanceCodec.attach("AVAILABLE=1\n", origin)
        assertEquals(raw, SelinuxContextValidityCarrierService.verifyPreloadedPayload(raw, current, 50_000_000L))
        val missing = SelinuxContextValidityCarrierService.carrierFailurePayload(
            SelinuxContextValidityCarrierService.PRELOAD_PAYLOAD_UNAVAILABLE,
            "No inherited preload",
        )
        assertEquals(missing, SelinuxContextValidityCarrierService.verifyPreloadedPayload(
            missing, current, 50_000_000L,
        ))
    }

    @Test fun `service rejects stale parent with a failed snapshot instead of stale findings`() {
        val raw = SelinuxCarrierProvenanceCodec.attach("AVAILABLE=1\n", origin)
        val rejected = SelinuxContextValidityCarrierService.verifyPreloadedPayload(
            raw, current.copy(apkPath = "/data/app/new/base.apk"), 50_000_000L,
        )
        val snapshot = SelinuxContextValidityBridge().parse(rejected)
        assertEquals(false, snapshot.available)
        assertEquals("App Zygote preload APK generation mismatch.", snapshot.failureReason)
        assertEquals(false, snapshot.dirtyPolicyAvailable)
    }
}

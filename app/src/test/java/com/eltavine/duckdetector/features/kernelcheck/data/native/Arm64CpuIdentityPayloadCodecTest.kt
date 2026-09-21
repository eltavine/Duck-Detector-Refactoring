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

package com.eltavine.duckdetector.features.kernelcheck.data.native

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class Arm64CpuIdentityPayloadCodecTest {

    @Test
    fun `parse observation keeps per cpu identity sources separate`() {
        val observation = Arm64CpuIdentityPayloadCodec.parseObservation(
            "7\t1\tSYSFS\t410fd4d0\t410fd4d0",
        )

        assertEquals(7, observation?.cpu)
        assertEquals(CachedCpuIdentitySource.SYSFS, observation?.cachedSource)
        assertEquals(0x410fd4d0L, observation?.cachedMidr)
        assertEquals(0x410fd4d0L, observation?.mrsMidr)
    }

    @Test
    fun `parse observation preserves unavailable values`() {
        val observation = Arm64CpuIdentityPayloadCodec.parseObservation(
            "2\t1\tNONE\tNA\tNA",
        )

        assertEquals(2, observation?.cpu)
        assertNull(observation?.cachedMidr)
        assertNull(observation?.mrsMidr)
    }

    @Test
    fun `malformed observation is ignored`() {
        assertNull(Arm64CpuIdentityPayloadCodec.parseObservation("0\t1\tSYSFS\tinvalid\t410fd4d0"))
        assertNull(Arm64CpuIdentityPayloadCodec.parseObservation("0\tmaybe\tNONE\tNA\tNA"))
    }

    @Test
    fun `status names from the native probe are parsed`() {
        assertEquals(
            Arm64CpuIdentityProbeStatus.COMPLETED,
            Arm64CpuIdentityPayloadCodec.parseStatus("COMPLETED"),
        )
        assertEquals(
            Arm64CpuIdentityProbeStatus.CPUID_EMULATION_UNAVAILABLE,
            Arm64CpuIdentityPayloadCodec.parseStatus("CPUID_EMULATION_UNAVAILABLE"),
        )
        assertEquals(
            Arm64CpuIdentityProbeStatus.AFFINITY_UNAVAILABLE,
            Arm64CpuIdentityPayloadCodec.parseStatus("AFFINITY_UNAVAILABLE"),
        )
        assertEquals(
            Arm64CpuIdentityProbeStatus.UNSUPPORTED_ABI,
            Arm64CpuIdentityPayloadCodec.parseStatus("UNSUPPORTED_ABI"),
        )
    }

    @Test
    fun `a status this build does not know becomes unknown rather than failing`() {
        assertEquals(
            Arm64CpuIdentityProbeStatus.UNKNOWN,
            Arm64CpuIdentityPayloadCodec.parseStatus("SOME_FUTURE_STATUS"),
        )
        assertEquals(
            Arm64CpuIdentityProbeStatus.UNKNOWN,
            Arm64CpuIdentityPayloadCodec.parseStatus(null),
        )
    }
}

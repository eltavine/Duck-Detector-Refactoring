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

package com.eltavine.duckdetector.features.dangerousapps.data.probes

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SceneDebugfsContextProbeTest {

    @Test
    fun `debugfs context on a dev mount is detected`() {
        val result = SceneDebugfsContextProbe(
            object : SceneDebugfsContextProbe.Transport {
                override fun mountLines(): List<String> = listOf(
                    "debugfs on /dev/qglcuqpa/debug type debugfs (rw,seclabel,relatime)",
                )

                override fun selinuxContext(path: String): String? {
                    return if (path == "/dev/qglcuqpa/debug") {
                        "u:object_r:debugfs:s0"
                    } else {
                        null
                    }
                }
            },
        ).probe()

        assertTrue(result.detected)
        assertTrue(result.detail.orEmpty().contains("/dev/qglcuqpa/debug"))
    }

    @Test
    fun `non debugfs context is ignored`() {
        val result = SceneDebugfsContextProbe().evaluate(
            mountPoints = listOf("/dev/pts"),
            contexts = mapOf("/dev/pts" to "u:object_r:device:s0"),
        )

        assertFalse(result.detected)
    }

    @Test
    fun `missing context is ignored`() {
        val result = SceneDebugfsContextProbe().evaluate(
            mountPoints = listOf("/dev/random/debug"),
            contexts = emptyMap(),
        )

        assertFalse(result.detected)
    }
}

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

class SceneLoopbackProbeTest {

    private val probe = SceneLoopbackProbe()

    @Test
    fun `scene http fingerprint is detected`() {
        val result = probe.evaluate(
            httpGet = SceneLoopbackProbe.ProbeExchange(
                connected = true,
                firstLine = "HTTP/1.1 404 Not Found",
            ),
            invalidPayload = SceneLoopbackProbe.ProbeExchange(
                connected = true,
                firstLine = "HTTP/1.1 400 Bad Request",
            ),
            sideChannel = SceneLoopbackProbe.ProbeExchange(
                connected = true,
                firstLine = null,
            ),
        )

        assertTrue(result.detected)
        assertTrue(result.get404Matched)
        assertTrue(result.invalid400Matched)
        assertTrue(result.sideChannelClosed)
        assertTrue(result.detail.orEmpty().contains("127.0.0.1:8765"))
        assertTrue(result.detail.orEmpty().contains("127.0.0.1:8788"))
    }

    @Test
    fun `generic localhost http server is ignored`() {
        val result = probe.evaluate(
            httpGet = SceneLoopbackProbe.ProbeExchange(
                connected = true,
                firstLine = "HTTP/1.1 200 OK",
            ),
            invalidPayload = SceneLoopbackProbe.ProbeExchange(
                connected = true,
                firstLine = "HTTP/1.1 400 Bad Request",
            ),
            sideChannel = SceneLoopbackProbe.ProbeExchange.unavailable(),
        )

        assertFalse(result.detected)
        assertFalse(result.get404Matched)
        assertTrue(result.invalid400Matched)
    }

    @Test
    fun `side channel alone does not create a hit`() {
        val result = probe.evaluate(
            httpGet = SceneLoopbackProbe.ProbeExchange.unavailable(),
            invalidPayload = SceneLoopbackProbe.ProbeExchange.unavailable(),
            sideChannel = SceneLoopbackProbe.ProbeExchange(
                connected = true,
                firstLine = null,
            ),
        )

        assertFalse(result.detected)
        assertFalse(result.sideChannelClosed)
    }
}

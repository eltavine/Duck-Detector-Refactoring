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

package com.eltavine.duckdetector.features.selinux.data.probes

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class SelinuxProcAttrCurrentPayloadCodecTest {

    @Test
    fun `round trips proc attr current result`() {
        val result = SelinuxProcAttrCurrentResult(
            label = "Magisk",
            targetContext = "u:r:magisk:s0",
            outcomeClass = SelinuxProcAttrCurrentResult.OUTCOME_DETECTED_NON_EINVAL,
            rawMessage = "ErrnoException: errno=13, Permission denied",
        )

        val decoded = SelinuxProcAttrCurrentPayloadCodec.decode(
            SelinuxProcAttrCurrentPayloadCodec.encode(result),
        )

        assertNotNull(decoded)
        assertEquals(result, decoded)
    }

    @Test
    fun `round trips separators embedded in every column`() {
        // Kernel strings and exception messages are not ours to assume. Before the columns were
        // escaped, a tab in any column but the last silently shifted every later column.
        val result = SelinuxProcAttrCurrentResult(
            label = "Magisk\tDenied",
            targetContext = "u:r:magisk:s0\nu:r:shell:s0",
            outcomeClass = "outcome\rclass",
            rawMessage = "ErrnoException: path=C:\\temp\terrno=13",
        )

        val decoded = SelinuxProcAttrCurrentPayloadCodec.decode(
            SelinuxProcAttrCurrentPayloadCodec.encode(result),
        )

        assertEquals(result, decoded)
    }

    @Test
    fun `encode keeps the four column layout when values carry tabs`() {
        val encoded = SelinuxProcAttrCurrentPayloadCodec.encode(
            SelinuxProcAttrCurrentResult(
                label = "a\tb",
                targetContext = "c",
                outcomeClass = "d",
                rawMessage = "e",
            ),
        )

        assertEquals("a\\tb\tc\td\te", encoded)
    }

    @Test
    fun `decode rejects a payload with the wrong column count`() {
        assertNull(SelinuxProcAttrCurrentPayloadCodec.decode("only\tthree\tcolumns"))
        assertNull(SelinuxProcAttrCurrentPayloadCodec.decode("a\tb\tc\td\te"))
    }
}

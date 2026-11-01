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

package com.eltavine.duckdetector.features.networkrisk.data.modules

import com.eltavine.duckdetector.features.networkrisk.domain.ObservationState
import org.junit.Assert.*
import org.junit.Test

class ProxyModuleMetadataTest {
    @Test fun `deployment identity and version are required without evaluating shell syntax`() {
        assertEquals(ObservationState.OBSERVED, parseModuleMetadata("id=box4\nversion=v5.1\n", "box4").state)
        listOf("id=box4\nversion=v5.1\nid=other", "id=other\nversion=v5.1", "id=box4\nversion=$(command)", "id=box4").forEach {
            assertEquals(ObservationState.INCONCLUSIVE, parseModuleMetadata(it, "box4").state)
        }
        assertEquals(ObservationState.INCONCLUSIVE, parseModuleMetadata("id=box4\nversion=" + "a".repeat(65), "box4").state)
    }
}

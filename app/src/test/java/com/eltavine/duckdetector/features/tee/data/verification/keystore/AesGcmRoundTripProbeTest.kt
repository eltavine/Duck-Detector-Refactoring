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

package com.eltavine.duckdetector.features.tee.data.verification.keystore

import android.os.Build
import android.security.keystore.KeyProperties
import org.junit.Assert.assertEquals
import org.junit.Test

class AesGcmRoundTripProbeTest {

    @Test
    fun `security level label maps trusted environment on android s and above`() {
        assertEquals(
            "TEE",
            keyInfoSecurityLevelLabel(
                sdkInt = Build.VERSION_CODES.S,
                securityLevel = KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
                insideSecureHardware = true,
            ),
        )
    }

    @Test
    fun `security level label falls back to secure hardware before android s`() {
        assertEquals(
            "SecureHardware",
            keyInfoSecurityLevelLabel(
                sdkInt = Build.VERSION_CODES.R,
                securityLevel = null,
                insideSecureHardware = true,
            ),
        )
    }

    @Test
    fun `security level label treats unknown secure as secure hardware`() {
        assertEquals(
            "SecureHardware",
            keyInfoSecurityLevelLabel(
                sdkInt = Build.VERSION_CODES.S,
                securityLevel = KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE,
                insideSecureHardware = true,
            ),
        )
    }

    @Test
    fun `security level label reports software when key is not hardware backed`() {
        assertEquals(
            "Software",
            keyInfoSecurityLevelLabel(
                sdkInt = Build.VERSION_CODES.R,
                securityLevel = null,
                insideSecureHardware = false,
            ),
        )
    }
}

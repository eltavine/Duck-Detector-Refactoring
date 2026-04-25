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

package com.eltavine.duckdetector.features.virtualization.data.native

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class VirtualizationRemoteSnapshotTest {

    @Test
    fun `parse handles extended payload with isolated profile`() {
        val separator = "\u001f"
        val snapshot = VirtualizationRemoteSnapshot.parse(
            """
            AVAILABLE=1
            PROFILE=ISOLATED
            NATIVE_AVAILABLE=1
            UID=99000
            PACKAGE_NAME=com.eltavine.duckdetector
            PROCESS_NAME=com.eltavine.duckdetector:isolated
            UID_NAME=u0_i321
            PACKAGES_FOR_UID=com.eltavine.duckdetector$separator com.example.sidecar
            CLASS_PATH_ENTRIES=/data/app/base.apk$separator/data/app/host.apk
            SOURCE_DIR=/data/app/base.apk
            SPLIT_SOURCE_DIRS=/data/app/split_config.arm64_v8a.apk
            MOUNT_NAMESPACE_INODE=mnt:[4026533000]
            APEX_MOUNT_KEY=1|8:1|/|/apex|ext4|/dev/block/dm-1
            SYSTEM_MOUNT_KEY=2|8:1|/|/system|ext4|/dev/block/dm-2
            VENDOR_MOUNT_KEY=3|8:1|/|/vendor|ext4|/dev/block/dm-3
            FILES_DIR=/data/user/0/com.eltavine.duckdetector/files
            CACHE_DIR=/data/user/0/com.eltavine.duckdetector/cache
            CODE_PATH=/data/app/base.apk
            FINDING=RUNTIME	WARNING	Graphics renderer	gfxstream	Google\ngfxstream\nOpenGL ES 3.2
            """.trimIndent(),
        )

        assertTrue(snapshot.available)
        assertEquals(VirtualizationRemoteProfile.ISOLATED, snapshot.profile)
        assertEquals(99000, snapshot.uid)
        assertEquals("com.eltavine.duckdetector:isolated", snapshot.processName)
        assertEquals(2, snapshot.packagesForUid.size)
        assertEquals(2, snapshot.classPathEntries.size)
        assertEquals("mnt:[4026533000]", snapshot.mountNamespaceInode)
        assertEquals("1|8:1|/|/apex|ext4|/dev/block/dm-1", snapshot.apexMountKey)
        assertEquals(1, snapshot.findings.size)
        assertEquals(1, snapshot.artifactKeys.size)
    }
}

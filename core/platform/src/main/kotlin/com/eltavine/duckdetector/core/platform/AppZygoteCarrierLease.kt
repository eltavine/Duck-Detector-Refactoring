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

package com.eltavine.duckdetector.core.platform

import android.os.IBinder
import android.os.RemoteException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/** Tracks a remote App-Zygote child until its Binder process actually dies. */
public class AppZygoteCarrierLease @JvmOverloads public constructor(
    gate: AppZygoteStartGate = AppZygoteStartGate.Default,
) : IBinder.DeathRecipient {

    private val gateLease = gate.acquireLease()
    private val remoteBinder = AtomicReference<IBinder?>(null)
    private val released = AtomicBoolean(false)

    /** True only while the observed remote Binder is still alive. */
    public val isActive: Boolean
        get() = !released.get() && remoteBinder.get()?.isBinderAlive == true

    /**
     * Starts observing the remote process. A successful unbind does not release the lease: the
     * child may still be alive, and ActivityManager only starts the App-Zygote retirement delay
     * after that child actually exits.
     */
    public fun attach(binder: IBinder): Boolean {
        if (released.get() || !binder.isBinderAlive) {
            release()
            return false
        }

        try {
            binder.linkToDeath(this, 0)
        } catch (_: RemoteException) {
            release()
            return false
        }

        if (!remoteBinder.compareAndSet(null, binder)) {
            runCatching { binder.unlinkToDeath(this, 0) }
            return false
        }

        // Death can race linkToDeath() and the reference publication above. Do not resurrect a
        // lease after binderDied() has already retired it.
        if (released.get() || !binder.isBinderAlive) {
            if (remoteBinder.compareAndSet(binder, null)) {
                runCatching { binder.unlinkToDeath(this, 0) }
            }
            release()
            return false
        }
        return true
    }

    /** Releases attempts that never obtained a live remote Binder. Attached leases wait for death. */
    public fun bindingFailed() {
        if (remoteBinder.get() == null) release()
    }

    public override fun binderDied() {
        release(unlink = false)
    }

    private fun release(unlink: Boolean = true) {
        if (!released.compareAndSet(false, true)) return
        val binder = remoteBinder.getAndSet(null)
        if (unlink && binder != null) {
            runCatching { binder.unlinkToDeath(this, 0) }
        }
        gateLease.close()
    }
}

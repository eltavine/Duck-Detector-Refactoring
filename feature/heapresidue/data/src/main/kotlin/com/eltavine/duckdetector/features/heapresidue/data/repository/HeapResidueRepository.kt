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

package com.eltavine.duckdetector.features.heapresidue.data.repository

import androidx.annotation.RequiresApi
import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.core.evidence.FailureName
import com.eltavine.duckdetector.features.heapresidue.data.HeapResidueReleases
import com.eltavine.duckdetector.features.heapresidue.data.hprof.ArtHprofScanner
import com.eltavine.duckdetector.features.heapresidue.data.hprof.HprofFormatException
import com.eltavine.duckdetector.features.heapresidue.data.ipc.DeadlinePipeInput
import com.eltavine.duckdetector.features.heapresidue.data.ipc.HeapCaptureSession
import com.eltavine.duckdetector.features.heapresidue.data.ipc.HeapDumpStatus
import com.eltavine.duckdetector.features.heapresidue.data.retention.HeapDumpRetention
import com.eltavine.duckdetector.features.heapresidue.domain.HeapResidueOutcome
import com.eltavine.duckdetector.features.heapresidue.domain.HeapResidueReport
import com.eltavine.duckdetector.features.heapresidue.domain.HeapResidueStage
import com.eltavine.duckdetector.features.heapresidue.domain.HeapResidueProbeFailure
import com.eltavine.duckdetector.features.heapresidue.domain.heapResidueOutcome
import com.eltavine.duckdetector.features.heapresidue.domain.HeapResidueRetention
import java.io.File
import java.net.SocketTimeoutException
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

class HeapResidueRepository(context: Context) : DetectorScanner<HeapResidueReport> {
    private val context = context.applicationContext

    override suspend fun scan(): HeapResidueReport = scanMutex.withLock {
        withContext(Dispatchers.IO) {
            val release = HeapResidueReleases.classify(Build.VERSION.SDK_INT)
            // Lint's API check sees only this comparison, not classify(); both reject the same releases.
            if (release == null || Build.VERSION.SDK_INT < HeapResidueReleases.FIRST_AUDITED_API) {
                return@withContext HeapResidueReport(stage = HeapResidueStage.READY, outcome = HeapResidueOutcome.UNSUPPORTED)
            }
            val report = try {
                withTimeoutOrNull(30_000) { collect() } ?: HeapResidueReport.failed("Heap capture timed out").copy(probeFailure = HeapResidueProbeFailure.TIMEOUT)
            } catch (cancellation: CancellationException) {
                throw cancellation
            } catch (failure: HprofFormatException) {
                HeapResidueReport(stage = HeapResidueStage.READY, outcome = HeapResidueOutcome.INCONCLUSIVE,
                    errorMessage = FailureName.describe(failure))
            } catch (failure: Exception) {
                HeapResidueReport.failed(FailureName.of(failure))
            }
            report.copy(release = release)
        }
    }

    @RequiresApi(HeapResidueReleases.FIRST_AUDITED_API)
    private suspend fun collect(): HeapResidueReport {
        val session = HeapCaptureSession(context)
        val pipes = ParcelFileDescriptor.createReliablePipe()
        var retention: HeapDumpRetention? = null
        var complete = false
        var connected = false
        try {
            val enabled = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
            retention = HeapDumpRetention(File(context.noBackupFilesDir, "heap-residue"), enabled)
            val service = session.connect()
            connected = true
            val deadline = SystemClock.elapsedRealtime() + 25_000
            session.start(service, pipes[1])
            val coroutine = currentCoroutineContext()
            val raw = DeadlinePipeInput(pipes[0], deadline) { coroutine.ensureActive() }
            val scan = ArtHprofScanner(HeapResidueTargets.packages, host = context.packageName).scan(retention.wrap(raw))
            val dump = session.result.await()
            complete = dump.status == HeapDumpStatus.COMPLETE
            val retained = retention.finish(complete)
            return HeapResidueReport(
                stage = HeapResidueStage.READY,
                outcome = heapResidueOutcome(complete, scan.candidates, scan.signals),
                probeFailure = when (dump.status) {
                    HeapDumpStatus.COMPLETE -> null
                    HeapDumpStatus.HIDDEN_API_UNAVAILABLE -> HeapResidueProbeFailure.HIDDEN_API
                    HeapDumpStatus.DUMP_FAILED, HeapDumpStatus.REUSED_PROCESS -> HeapResidueProbeFailure.DUMP
                },
                signals = if (complete) scan.signals else emptyList(),
                bytesRead = scan.bytesRead, candidateCount = scan.candidates,
                captureAgeMillis = dump.ageMillis, dumpDurationMillis = dump.durationMillis,
                gcCountBefore = dump.gcCountBefore.takeIf { it >= 0 }, retention = retained,
            )
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (failure: Exception) {
            // Closing the reader also releases a producer blocked by pipe backpressure.
            runCatching { pipes[0].close() }
            val dump = if (connected) withTimeoutOrNull(500) { session.result.await() } else null
            val reason = when {
                !connected -> HeapResidueProbeFailure.BINDING
                dump?.status == HeapDumpStatus.HIDDEN_API_UNAVAILABLE -> HeapResidueProbeFailure.HIDDEN_API
                dump != null && dump.status != HeapDumpStatus.COMPLETE -> HeapResidueProbeFailure.DUMP
                failure is SocketTimeoutException -> HeapResidueProbeFailure.TIMEOUT
                failure is HprofFormatException -> HeapResidueProbeFailure.MALFORMED_HPROF
                else -> HeapResidueProbeFailure.STREAM
            }
            return HeapResidueReport(
                stage = HeapResidueStage.READY,
                outcome = if (reason == HeapResidueProbeFailure.MALFORMED_HPROF) HeapResidueOutcome.INCONCLUSIVE
                    else HeapResidueOutcome.UNAVAILABLE,
                probeFailure = reason, errorMessage = FailureName.of(failure),
                retention = retention?.finish(false) ?: HeapResidueRetention.FAILED,
            )
        } finally {
            retention?.finish(complete)
            pipes.forEach { runCatching { it.close() } }
            session.close()
        }
    }

    private companion object {
        // Serializes this expensive feature across SDK sessions and reserves one debug spool at a time.
        val scanMutex = Mutex()
    }
}

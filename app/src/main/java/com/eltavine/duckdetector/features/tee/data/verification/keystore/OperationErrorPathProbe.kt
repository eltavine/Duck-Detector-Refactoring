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
import com.eltavine.duckdetector.features.tee.data.keystore.AndroidKeyStoreTools

class OperationErrorPathProbe(
    private val binderClient: Keystore2PrivateBinderClient = Keystore2PrivateBinderClient(),
) {

    fun inspect(): OperationErrorPathResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return OperationErrorPathResult(
                executed = false,
                detail = "Operation error-path probe requires Android 12 or newer.",
            )
        }
        val keyStore = AndroidKeyStoreTools.loadKeyStore()
        val alias = "duck_operation_err_${System.nanoTime()}"
        return runCatching {
            AndroidKeyStoreTools.generateSigningEcKey(
                keyStore = keyStore,
                alias = alias,
                subject = "CN=DuckDetector Operation Error, O=Eltavine",
                useStrongBox = false,
            )
            val service = binderClient.getKeystoreService()
                ?: return OperationErrorPathResult(
                    executed = false,
                    detail = "Keystore2 service interface was unavailable.",
                )
            val response = binderClient.getKeyEntryResponse(service, binderClient.createKeyDescriptor(alias))
                ?: return OperationErrorPathResult(
                    executed = true,
                    detail = "Keystore2 getKeyEntry() returned null for the probe alias.",
                )
            val returnedDescriptor = binderClient.getReturnedDescriptor(response)
            val descriptor = when {
                returnedDescriptor == null -> binderClient.createKeyDescriptor(alias)
                binderClient.getDescriptorDomain(returnedDescriptor) == binderClient.getDomainKeyId() -> returnedDescriptor
                else -> {
                    val namespace = binderClient.getDescriptorNamespace(returnedDescriptor)
                        ?: return OperationErrorPathResult(
                            executed = true,
                            detail = "Keystore2 returned a non-KEY_ID descriptor without namespace information.",
                        )
                    binderClient.createKeyIdDescriptor(namespace, alias)
                }
            }
            val securityLevel = binderClient.getSecurityLevelBinder(response)
                ?: binderClient.resolveSecurityLevel(
                    service,
                    Keystore2PrivateBinderClient.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
                )
                ?: return OperationErrorPathResult(
                    executed = true,
                    detail = "IKeystoreSecurityLevel binder was unavailable.",
                )

            val minimalParams = binderClient.createSigningOperationParameters()
            val minimalOperation = createOperation(securityLevel, descriptor, minimalParams)
            val activeParams = if (minimalOperation.succeeded) {
                minimalParams
            } else {
                val compatParams = binderClient.createSigningOperationParametersWithAlgorithm()
                val compatOperation = createOperation(securityLevel, descriptor, compatParams)
                if (!compatOperation.succeeded) {
                    return OperationErrorPathResult(
                        executed = true,
                        detail = compatOperation.detail ?: "createOperation failed for both minimal and compatibility params.",
                    )
                }
                compatParams
            }

            val updateAadServiceSpecific = probeUpdateAad(securityLevel, descriptor, activeParams)
            val oversizedUpdateRejected = probeOversizedUpdate(securityLevel, descriptor, activeParams)
            val abortInvalidatedHandle = probeAbortInvalidatesHandle(securityLevel, descriptor, activeParams)

            OperationErrorPathResult(
                executed = true,
                createOperationSucceeded = true,
                updateAadServiceSpecific = updateAadServiceSpecific,
                oversizedUpdateRejected = oversizedUpdateRejected,
                abortInvalidatedHandle = abortInvalidatedHandle,
                fallbackCompatParamsUsed = !minimalOperation.succeeded,
                detail = "updateAadServiceSpecific=$updateAadServiceSpecific, oversizedUpdateRejected=$oversizedUpdateRejected, abortInvalidatedHandle=$abortInvalidatedHandle, compatFallback=${!minimalOperation.succeeded}",
            )
        }.getOrElse { throwable ->
            OperationErrorPathResult(
                executed = true,
                detail = throwable.message ?: "Operation error-path probe failed.",
            )
        }.also {
            AndroidKeyStoreTools.safeDelete(keyStore, alias)
        }
    }

    private fun probeUpdateAad(
        securityLevel: Any,
        descriptor: Any,
        parameters: List<Any>,
    ): Boolean {
        val created = createOperation(securityLevel, descriptor, parameters)
        val operation = created.operation ?: return false
        return try {
            binderClient.updateAadOperation(operation, "aad".encodeToByteArray())
            false
        } catch (throwable: Throwable) {
            binderClient.isServiceSpecificException(throwable)
        } finally {
            runCatching { binderClient.abortOperation(operation) }
        }
    }

    private fun probeOversizedUpdate(
        securityLevel: Any,
        descriptor: Any,
        parameters: List<Any>,
    ): Boolean {
        val created = createOperation(securityLevel, descriptor, parameters)
        val operation = created.operation ?: return false
        return try {
            binderClient.updateOperation(operation, ByteArray(LARGE_INPUT_SIZE))
            false
        } catch (throwable: Throwable) {
            binderClient.isServiceSpecificException(throwable)
        } finally {
            runCatching { binderClient.abortOperation(operation) }
        }
    }

    private fun probeAbortInvalidatesHandle(
        securityLevel: Any,
        descriptor: Any,
        parameters: List<Any>,
    ): Boolean {
        val created = createOperation(securityLevel, descriptor, parameters)
        val operation = created.operation ?: return false
        return try {
            binderClient.abortOperation(operation)
            binderClient.updateOperation(operation, "after_abort".encodeToByteArray())
            false
        } catch (throwable: Throwable) {
            val expectedInvalidHandle =
                binderClient.getKeyMintErrorCodeValue("INVALID_OPERATION_HANDLE") ?: INVALID_OPERATION_HANDLE_FALLBACK
            binderClient.isServiceSpecificException(throwable) &&
                binderClient.extractServiceSpecificErrorCode(throwable) == expectedInvalidHandle
        }
    }

    private fun createOperation(
        securityLevel: Any,
        descriptor: Any,
        parameters: List<Any>,
    ): CreatedOperation {
        return runCatching {
            val response = binderClient.createOperation(securityLevel, descriptor, parameters)
            CreatedOperation(
                succeeded = true,
                operation = binderClient.getOperationHandle(response),
            )
        }.getOrElse { throwable ->
            CreatedOperation(
                succeeded = false,
                detail = binderClient.describeThrowable(throwable),
            )
        }
    }

    private data class CreatedOperation(
        val succeeded: Boolean,
        val operation: Any? = null,
        val detail: String? = null,
    )

    companion object {
        private const val LARGE_INPUT_SIZE = 0x8001
        private const val INVALID_OPERATION_HANDLE_FALLBACK = -28
    }
}

data class OperationErrorPathResult(
    val executed: Boolean,
    val createOperationSucceeded: Boolean = false,
    val updateAadServiceSpecific: Boolean = false,
    val oversizedUpdateRejected: Boolean = false,
    val abortInvalidatedHandle: Boolean = false,
    val fallbackCompatParamsUsed: Boolean = false,
    val detail: String,
)

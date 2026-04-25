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
import android.os.IBinder
import android.os.Parcel
import org.lsposed.hiddenapibypass.HiddenApiBypass
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import java.lang.reflect.Proxy
import java.security.SecureRandom

/**
 * 通过隐藏 API 打开一个“只对当前探针可见”的 Keystore2 私有代理会话，避免把全局 ServiceManager 状态污染给其他探针。
 * Opens a Keystore2 private proxy session that is scoped to the current probe so other probes keep seeing the real ServiceManager state.
 */
class Keystore2PrivateBinderClient {

    fun lookupBinder(): IBinder? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return null
        }
        ensureHiddenApiAccess()
        return runCatching {
            val serviceManager = loadClass("android.os.ServiceManager")
            val getService = serviceManager.getMethod("getService", String::class.java)
            getService.invoke(null, SERVICE_NAME) as? IBinder
        }.getOrNull()
    }

    fun buildGetKeyEntryRequest(alias: String): Keystore2BinderRequest {
        return Keystore2BinderRequest(
            interfaceDescriptor = INTERFACE_DESCRIPTOR,
            transactionCode = TRANSACTION_GET_KEY_ENTRY,
            alias = alias,
        ) { data ->
            data.writeInterfaceToken(INTERFACE_DESCRIPTOR)
            data.writeInt(1)
            data.writeInt(0)
            data.writeLong(-1L)
            data.writeString(alias)
            data.writeByteArray(null)
        }
    }

    fun executeRequest(
        binder: IBinder,
        request: Keystore2BinderRequest,
    ): BinderTransactionResult {
        val data = Parcel.obtain()
        val reply = Parcel.obtain()
        return try {
            request.writeTo(data)
            val success = binder.transact(request.transactionCode, data, reply, 0)
            val snapshot = captureReplySnapshot(reply)
            BinderTransactionResult(
                success = success,
                replySnapshot = snapshot,
                replyFailureReason = if (success) null else "Keystore2 transact() returned false for alias=${request.alias}",
            )
        } catch (throwable: Throwable) {
            BinderTransactionResult(
                success = false,
                throwable = throwable,
                replyFailureReason = throwable.message ?: "Keystore2 transact failed for alias=${request.alias}",
            )
        } finally {
            data.recycle()
            reply.recycle()
        }
    }

    fun transactGetKeyEntry(binder: IBinder, alias: String): BinderTransactionResult {
        return executeRequest(binder, buildGetKeyEntryRequest(alias))
    }

    fun openSession(
        useStrongBox: Boolean = false,
        captureGenerateKeyReplies: Boolean = false,
    ): Keystore2PrivateSessionResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return Keystore2PrivateSessionResult(
                failureReason = "Keystore2 private binder proxy requires Android 12 or newer.",
            )
        }

        ensureHiddenApiAccess()
        val binder = lookupBinder() ?: return Keystore2PrivateSessionResult(
            failureReason = "Keystore2 binder endpoint was not available.",
        )
        // 这里统一收集会话内所有隐藏接口异常，供 timing side-channel 在 skip 时做静态签名判定。
        // Collect every hidden-interface failure for this session so timing side-channel can still classify skip-mode signatures.
        val diagnosticsCollector = CapturedThrowableCollector()
        val service = createPrivateKeystoreServiceProxy(
            rawBinder = binder,
            diagnosticsCollector = diagnosticsCollector,
            captureGenerateKeyReplies = captureGenerateKeyReplies,
        ) ?: return Keystore2PrivateSessionResult(
            failureReason = "Keystore2 service interface was not available after opening the private binder session.",
            capturedFailures = diagnosticsCollector.snapshot(),
        )
        val securityLevel = resolveSecurityLevel(
            service = service,
            level = if (useStrongBox) SECURITY_LEVEL_STRONGBOX else SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
        ) ?: return Keystore2PrivateSessionResult(
            failureReason = "Keystore2 security level proxy was not available.",
            capturedFailures = diagnosticsCollector.snapshot(),
        )

        val session = Keystore2PrivateSession(
            binder = binder,
            service = service,
            securityLevel = securityLevel,
            proxyInstalled = true,
            serviceProxyActive = Proxy.isProxyClass(service.javaClass),
            securityLevelProxyActive = Proxy.isProxyClass(securityLevel.javaClass),
            diagnosticsCollector = diagnosticsCollector,
        )
        return if (!session.serviceProxyActive || !session.securityLevelProxyActive) {
            Keystore2PrivateSessionResult(
                failureReason = "Keystore2 private binder proxy did not wrap both service and security-level interfaces.",
                capturedFailures = diagnosticsCollector.snapshot(),
            )
        } else {
            Keystore2PrivateSessionResult(session = session)
        }
    }

    fun closeSession(session: Keystore2PrivateSession) {
        generateKeyReplyCaptureSlot.remove()
    }

    fun createKeyDescriptor(alias: String): Any {
        val descriptorClass = loadClass(CLASS_KEY_DESCRIPTOR)
        val descriptor = descriptorClass.getDeclaredConstructor().newInstance()
        setField(descriptor, "domain", 0)
        setField(descriptor, "nspace", -1L)
        setField(descriptor, "alias", alias)
        setField(descriptor, "blob", null)
        return descriptor
    }

    fun generateAttestationKey(securityLevel: Any, keyDescriptor: Any): Any? {
        var lastFailure: Throwable? = null
        val parameterSets = listOf(
            listOf(
                createKeyParameter(0x10000002, 3),
                createKeyParameter(0x30000003, 256),
                createKeyParameter(0x1000000A, 1),
                createKeyParameter(0x20000001, 7),
                createKeyParameter(0x20000005, 4),
                createKeyParameter(0x700001F7, true),
            ),
            listOf(
                createKeyParameter(0x10000002, 3),
                createKeyParameter(0x30000003, 256),
                createKeyParameter(0x1000000A, 1),
                createKeyParameter(0x20000001, 7),
                createKeyParameter(0x20000005, 0),
                createKeyParameter(0x700001F7, true),
            ),
            listOf(
                createKeyParameter(0x10000002, 3),
                createKeyParameter(0x30000003, 256),
                createKeyParameter(0x1000000A, 1),
                createKeyParameter(0x20000001, 7),
                createKeyParameter(0x700001F7, true),
            ),
        )

        for (parameters in parameterSets) {
            try {
                return invokeGenerateKey(securityLevel, keyDescriptor, null, parameters)
            } catch (throwable: Throwable) {
                lastFailure = throwable
            }
        }

        throw lastFailure ?: IllegalStateException("Unable to provision PURPOSE_ATTEST_KEY test key.")
    }

    fun generateSigningKey(
        securityLevel: Any,
        keyDescriptor: Any,
        attestationKeyDescriptor: Any?,
        attest: Boolean,
    ): Any? {
        val parameters = buildSigningKeyParameters(attest)
        return invokeGenerateKey(securityLevel, keyDescriptor, attestationKeyDescriptor, parameters)
    }

    fun captureGenerateKeyReply(useStrongBox: Boolean = false): GenerateKeyReplyCaptureResult {
        val sessionResult = openSession(
            useStrongBox = useStrongBox,
            captureGenerateKeyReplies = true,
        )
        val session = sessionResult.session ?: return GenerateKeyReplyCaptureResult(
            available = false,
            detail = sessionResult.failureReason ?: "Keystore2 private binder proxy session unavailable.",
        )
        val alias = "${DEFAULT_GENERATE_MODE_ALIAS_PREFIX}_${System.nanoTime()}"
        val keyDescriptor = createKeyDescriptor(alias)

        return try {
            val capture = invokeGenerateKeyWithReplyCapture(
                securityLevel = session.securityLevel,
                keyDescriptor = keyDescriptor,
                attestationKeyDescriptor = null,
                parameters = buildGenerateModeSigningKeyParameters(),
            )
            when {
                capture.rawReply != null -> GenerateKeyReplyCaptureResult(
                    available = true,
                    rawReply = capture.rawReply,
                    rawPrefix = capture.rawPrefix,
                    detail = buildString {
                        append("Captured generateKey reply via private binder proxy transact")
                        append("; bytes=")
                        append(capture.rawReply.size)
                        capture.transactionCode?.let {
                            append(", code=")
                            append(it)
                        }
                        capture.transactReturned?.let {
                            append(", transactReturned=")
                            append(it)
                        }
                        capture.throwable?.let {
                            append(", invocation=")
                            append(describeThrowable(it))
                        }
                    },
                )
                else -> GenerateKeyReplyCaptureResult(
                    available = false,
                    detail = capture.failureReason
                        ?: capture.throwable?.let(::describeThrowable)
                        ?: "generateKey reply capture did not observe a marshalled reply.",
                )
            }
        } catch (throwable: Throwable) {
            GenerateKeyReplyCaptureResult(
                available = false,
                detail = describeThrowable(throwable),
            )
        } finally {
            deleteKey(session.service, keyDescriptor)
            closeSession(session)
        }
    }

    fun getKeyEntry(service: Any, keyDescriptor: Any) {
        getKeyEntryResponse(service, keyDescriptor)
    }

    fun getKeyEntryResponse(service: Any, keyDescriptor: Any): Any? {
        return service.javaClass
            .getMethod("getKeyEntry", keyDescriptor.javaClass)
            .invoke(service, keyDescriptor)
    }

    fun getMetadata(keyEntryResponse: Any): Any? = getFieldValue(keyEntryResponse, "metadata")

    fun getReturnedDescriptor(keyEntryResponse: Any): Any? {
        return getMetadata(keyEntryResponse)?.let { metadata ->
            getFieldValue(metadata, "key")
        } ?: getFieldValue(keyEntryResponse, "key")
    }

    fun resolveFollowUpDescriptor(requestedDescriptor: Any, keyMetadataOrResponse: Any?): Any {
        val returnedDescriptor = keyMetadataOrResponse?.let(::getReturnedDescriptor) ?: return requestedDescriptor
        val returnedNamespace = getDescriptorNamespace(returnedDescriptor)
        val keyIdDomain = getDomainKeyId()
        return when {
            // AOSP 在成功生成后可能把后续操作入口切到 KEY_ID 语义；继续拿原 alias descriptor 调隐藏接口，部分设备会直接打成 KEY_NOT_FOUND。
            // AOSP may switch follow-up operations to KEY_ID semantics after generateKey; reusing the original alias descriptor can trigger KEY_NOT_FOUND on some devices.
            getDescriptorDomain(returnedDescriptor) == keyIdDomain -> returnedDescriptor
            returnedNamespace != null && returnedNamespace >= 0L -> createKeyIdDescriptor(
                nspace = returnedNamespace,
                aliasHint = getDescriptorAlias(requestedDescriptor),
            )
            else -> returnedDescriptor
        }
    }

    fun getSecurityLevelBinder(keyEntryResponse: Any): Any? = getFieldValue(keyEntryResponse, "iSecurityLevel")

    fun getMetadataSecurityLevel(keyEntryResponse: Any): Any? {
        val metadata = getMetadata(keyEntryResponse) ?: return null
        return getFieldValue(metadata, "keySecurityLevel")
    }

    fun getPureCertSecurityLevel(keyEntryResponse: Any): Any? {
        getSecurityLevelBinder(keyEntryResponse)?.let { return it }
        return getMetadataSecurityLevel(keyEntryResponse)
    }

    fun getMetadataModificationTimeMs(metadata: Any): Long? {
        val raw = getFieldValue(metadata, "modificationTimeMs") ?: return null
        return when (raw) {
            is Long -> raw
            is Int -> raw.toLong()
            else -> null
        }
    }

    fun getMetadataAuthorizations(metadata: Any): Array<Any?> {
        return toObjectArray(getFieldValue(metadata, "authorizations"))
    }

    fun getAuthorizationTag(authorization: Any): Int? {
        val keyParameter = getFieldValue(authorization, "keyParameter") ?: return null
        return getFieldValue(keyParameter, "tag") as? Int
    }

    fun createKeyIdDescriptor(nspace: Long, aliasHint: String? = null): Any {
        val descriptorClass = loadClass(CLASS_KEY_DESCRIPTOR)
        val descriptor = descriptorClass.getDeclaredConstructor().newInstance()
        setField(descriptor, "domain", getDomainKeyId())
        setField(descriptor, "nspace", nspace)
        setField(descriptor, "alias", aliasHint)
        setField(descriptor, "blob", null)
        return descriptor
    }

    fun getDescriptorDomain(descriptor: Any): Int? = getFieldValue(descriptor, "domain") as? Int

    fun getDescriptorAlias(descriptor: Any): String? = getFieldValue(descriptor, "alias") as? String

    fun getDescriptorNamespace(descriptor: Any): Long? {
        val raw = getFieldValue(descriptor, "nspace") ?: return null
        return when (raw) {
            is Long -> raw
            is Int -> raw.toLong()
            else -> null
        }
    }

    fun getDomainKeyId(): Int {
        return runCatching {
            val domainClass = loadClass("android.system.keystore2.Domain")
            domainClass.getField("KEY_ID").getInt(null)
        }.getOrDefault(DOMAIN_KEY_ID_FALLBACK)
    }

    fun getTagValue(name: String): Int? {
        return runCatching {
            val tagClass = loadClass("android.hardware.security.keymint.Tag")
            tagClass.getField(name).getInt(null)
        }.getOrNull()
    }

    fun getKeyPurposeValue(name: String): Int? {
        return runCatching {
            val purposeClass = loadClass("android.hardware.security.keymint.KeyPurpose")
            purposeClass.getField(name).getInt(null)
        }.getOrNull()
    }

    fun getDigestValue(name: String): Int? {
        return runCatching {
            val digestClass = loadClass("android.hardware.security.keymint.Digest")
            digestClass.getField(name).getInt(null)
        }.getOrNull()
    }

    fun getAlgorithmValue(name: String): Int? {
        return runCatching {
            val algorithmClass = loadClass("android.hardware.security.keymint.Algorithm")
            algorithmClass.getField(name).getInt(null)
        }.getOrNull()
    }

    fun getKeyMintErrorCodeValue(name: String): Int? {
        return runCatching {
            val errorCodeClass = loadClass("android.hardware.security.keymint.ErrorCode")
            errorCodeClass.getField(name).getInt(null)
        }.getOrNull()
    }

    fun deleteKey(service: Any, keyDescriptor: Any) {
        runCatching {
            service.javaClass
                .getMethod("deleteKey", keyDescriptor.javaClass)
                .invoke(service, keyDescriptor)
        }
    }

    fun listEntries(service: Any): Array<Any?> {
        val method = service.javaClass.methods.firstOrNull {
            it.name == "listEntries" && it.parameterTypes.size >= 2
        } ?: throw NoSuchMethodException("Unable to find hidden listEntries on ${service.javaClass.name}")
        method.isAccessible = true
        return toObjectArray(method.invoke(service, *buildListEntriesArgs(method.parameterTypes)))
    }

    fun listEntriesBatched(service: Any, startPastAlias: String): Array<Any?> {
        val method = service.javaClass.methods.firstOrNull {
            it.name == "listEntriesBatched" && it.parameterTypes.size >= 3
        } ?: throw NoSuchMethodException("Unable to find hidden listEntriesBatched on ${service.javaClass.name}")
        method.isAccessible = true
        return toObjectArray(method.invoke(service, *buildListEntriesArgs(method.parameterTypes, startPastAlias)))
    }

    fun createTimingAliases(prefix: String = DEFAULT_ALIAS_PREFIX): TimingKeyAliases {
        val suffix = System.nanoTime()
        return TimingKeyAliases(
            aliasPrefix = prefix,
            attestedAlias = "${prefix}_Attested_$suffix",
            nonAttestedAlias = "${prefix}_NonAttested_$suffix",
            attestKeyAlias = "${prefix}_AttestKey_$suffix",
        )
    }

    fun createSigningOperationParameters(): List<Any> {
        val purposeTag = getTagValue("PURPOSE") ?: 0x10000001
        val digestTag = getTagValue("DIGEST") ?: 0x20000005
        val signPurpose = getKeyPurposeValue("SIGN") ?: 2
        val sha256Digest = getDigestValue("SHA_2_256") ?: 4
        return listOf(
            createKeyParameter(purposeTag, signPurpose),
            createKeyParameter(digestTag, sha256Digest),
        )
    }

    fun createSigningOperationParametersWithAlgorithm(): List<Any> {
        val algorithmTag = getTagValue("ALGORITHM") ?: 0x10000002
        val ecAlgorithm = getAlgorithmValue("EC") ?: 3
        return createSigningOperationParameters() + createKeyParameter(algorithmTag, ecAlgorithm)
    }

    fun createOperation(
        securityLevel: Any,
        keyDescriptor: Any,
        parameters: List<Any>,
    ): Any? {
        val keyParameterClass = loadClass(CLASS_KEY_PARAMETER)
        val array = java.lang.reflect.Array.newInstance(keyParameterClass, parameters.size)
        parameters.forEachIndexed { index, value ->
            java.lang.reflect.Array.set(array, index, value)
        }
        securityLevel.javaClass.methods.firstOrNull {
            it.name == "createOperation" &&
                it.parameterTypes.size == 3 &&
                it.parameterTypes[0].isAssignableFrom(keyDescriptor.javaClass) &&
                it.parameterTypes[1].isArray &&
                (it.parameterTypes[2] == Boolean::class.javaPrimitiveType ||
                    it.parameterTypes[2] == Boolean::class.java)
        }?.let { exactMethod ->
            exactMethod.isAccessible = true
            return exactMethod.invoke(securityLevel, keyDescriptor, array, false)
        }
        val createOperationMethod = securityLevel.javaClass.methods.firstOrNull {
            it.name == "createOperation" && it.parameterTypes.isNotEmpty()
        } ?: throw NoSuchMethodException("Unable to find hidden createOperation on ${securityLevel.javaClass.name}")
        createOperationMethod.isAccessible = true
        val args = createOperationMethod.parameterTypes.mapIndexed { index, type ->
            when {
                index == 0 -> keyDescriptor
                index == 1 && type.isArray -> array
                type == Boolean::class.javaPrimitiveType || type == Boolean::class.java -> false
                type == Int::class.javaPrimitiveType || type == Int::class.java -> 0
                type == Long::class.javaPrimitiveType || type == Long::class.java -> 0L
                type == ByteArray::class.java -> ByteArray(0)
                else -> null
            }
        }.toTypedArray()
        return createOperationMethod.invoke(securityLevel, *args)
    }

    fun getOperationHandle(createOperationResponse: Any?): Any? {
        if (createOperationResponse == null) {
            return null
        }
        return getFieldValue(createOperationResponse, "iOperation")
            ?: getFieldValue(createOperationResponse, "operation")
    }

    fun getCertificateBlob(keyEntryResponse: Any): ByteArray? {
        return (getFieldValue(keyEntryResponse, "certificate") as? ByteArray)
            ?: (getMetadata(keyEntryResponse)?.let { getFieldValue(it, "certificate") } as? ByteArray)
    }

    fun getCertificateChainBlob(keyEntryResponse: Any): ByteArray? {
        return (getFieldValue(keyEntryResponse, "certificateChain") as? ByteArray)
            ?: (getMetadata(keyEntryResponse)?.let { getFieldValue(it, "certificateChain") } as? ByteArray)
    }

    fun abortOperation(operation: Any?) {
        if (operation == null) {
            return
        }
        operation.javaClass.getMethod("abort").invoke(operation)
    }

    fun updateOperation(operation: Any, input: ByteArray): Any? {
        return operation.javaClass.getMethod("update", ByteArray::class.java).invoke(operation, input)
    }

    fun updateAadOperation(operation: Any, input: ByteArray): Any? {
        return operation.javaClass.getMethod("updateAad", ByteArray::class.java).invoke(operation, input)
    }

    fun isServiceSpecificException(throwable: Throwable): Boolean {
        return findThrowable(throwable) { it.javaClass.name == "android.os.ServiceSpecificException" } != null
    }

    fun extractServiceSpecificErrorCode(throwable: Throwable): Int? {
        val serviceSpecific = findThrowable(throwable) {
            it.javaClass.name == "android.os.ServiceSpecificException"
        } ?: return null
        return getFieldValue(serviceSpecific, "errorCode") as? Int
    }

    fun describeThrowable(throwable: Throwable): String {
        val root = findRootCause(throwable)
        val serviceSpecificCode = extractServiceSpecificErrorCode(throwable)
        val detail = root.message?.takeIf { it.isNotBlank() }
        return when {
            serviceSpecificCode != null && detail != null -> "${root.javaClass.simpleName}(code $serviceSpecificCode): $detail"
            serviceSpecificCode != null -> "${root.javaClass.simpleName}(code $serviceSpecificCode)"
            detail != null -> "${root.javaClass.simpleName}: $detail"
            else -> root.javaClass.simpleName
        }
    }

    private fun invokeGenerateKey(
        securityLevel: Any,
        keyDescriptor: Any,
        attestationKeyDescriptor: Any?,
        parameters: List<Any>,
    ): Any? {
        val invocation = buildGenerateKeyInvocation(
            securityLevel = securityLevel,
            keyDescriptor = keyDescriptor,
            attestationKeyDescriptor = attestationKeyDescriptor,
            parameters = parameters,
        )
        return invokeProxyMethod(invocation.target, invocation.method, invocation.args)
    }

    private fun invokeGenerateKeyWithReplyCapture(
        securityLevel: Any,
        keyDescriptor: Any,
        attestationKeyDescriptor: Any?,
        parameters: List<Any>,
    ): GenerateKeyReplyCaptureSnapshot {
        val invocation = buildGenerateKeyInvocation(
            securityLevel = securityLevel,
            keyDescriptor = keyDescriptor,
            attestationKeyDescriptor = attestationKeyDescriptor,
            parameters = parameters,
        )
        val slot = GenerateKeyReplyCaptureSlot()
        generateKeyReplyCaptureSlot.set(slot)
        return try {
            runCatching {
                invokeProxyMethod(invocation.target, invocation.method, invocation.args)
            }.fold(
                onSuccess = {
                    slot.toSnapshot(
                        defaultFailureReason = "generateKey completed without an observable reply payload.",
                    )
                },
                onFailure = { throwable ->
                    slot.toSnapshot(
                        throwable = throwable,
                        defaultFailureReason = "generateKey failed before the private binder proxy captured a reply.",
                    )
                },
            )
        } finally {
            generateKeyReplyCaptureSlot.remove()
        }
    }

    private fun buildGenerateKeyInvocation(
        securityLevel: Any,
        keyDescriptor: Any,
        attestationKeyDescriptor: Any?,
        parameters: List<Any>,
    ): HiddenMethodInvocation {
        val keyParameterClass = loadClass(CLASS_KEY_PARAMETER)
        val array = java.lang.reflect.Array.newInstance(keyParameterClass, parameters.size)
        parameters.forEachIndexed { index, value ->
            java.lang.reflect.Array.set(array, index, value)
        }
        val generateKeyMethod = securityLevel.javaClass.methods.firstOrNull {
            it.name == "generateKey" && it.parameterTypes.size == 5
        } ?: throw NoSuchMethodException("Unable to find hidden generateKey signature on ${securityLevel.javaClass.name}")
        generateKeyMethod.isAccessible = true
        return HiddenMethodInvocation(
            target = securityLevel,
            method = generateKeyMethod,
            args = arrayOf(
                keyDescriptor,
                attestationKeyDescriptor,
                array,
                0,
                ByteArray(0),
            ),
        )
    }

    private fun buildSigningKeyParameters(attest: Boolean): List<Any> {
        return buildList {
            add(createKeyParameter(0x10000002, 3))
            add(createKeyParameter(0x30000003, 256))
            add(createKeyParameter(0x1000000A, 1))
            add(createKeyParameter(0x20000001, 2))
            add(createKeyParameter(0x20000005, 4))
            add(createKeyParameter(0x700001F7, true))
            if (attest) {
                add(createKeyParameter(0x900002C4.toInt(), ByteArray(32).also(SecureRandom()::nextBytes)))
            }
        }
    }

    private fun buildGenerateModeSigningKeyParameters(): List<Any> {
        return buildList {
            add(createKeyParameter(0x10000002, 3))
            add(createKeyParameter(0x1000000A, 1))
            add(createKeyParameter(0x20000005, 4))
            add(createKeyParameter(0x20000001, 2))
            add(createKeyParameter(0x900002C4.toInt(), ByteArray(32).also(SecureRandom()::nextBytes)))
            add(createKeyParameter(0x700001F7, true))
        }
    }

    private fun createKeyParameter(tag: Int, value: Any): Any {
        val parameterClass = loadClass(CLASS_KEY_PARAMETER)
        val parameter = parameterClass.getDeclaredConstructor().newInstance()
        setField(parameter, "tag", tag)

        val valueClass = loadClass(CLASS_KEY_PARAMETER_VALUE)
        val valueObject = createKeyParameterValue(valueClass, tag, value)
        setField(parameter, "value", valueObject)
        return parameter
    }

    private fun createKeyParameterValue(valueClass: Class<*>, tag: Int, value: Any): Any {
        val valueObject = valueClass.getDeclaredConstructor().newInstance()
        val setterName = keyParameterSetterNameForTag(tag)
        val parameterType = keyParameterParameterType(value)

        try {
            // KeyParameterValue 是 AIDL union，优先按真实 setter + 参数类型写值；只有签名被 OEM 改形时才退到名称匹配。
            // KeyParameterValue is an AIDL union, so we prefer the real setter + parameter type and only fall back to name matching for OEM-shaped signatures.
            val setter = valueClass.getDeclaredMethod(setterName, parameterType)
            setter.isAccessible = true
            setter.invoke(valueObject, value)
        } catch (_: NoSuchMethodException) {
            val setter = valueClass.declaredMethods.firstOrNull {
                it.name == setterName && it.parameterTypes.size == 1
            } ?: throw NoSuchMethodException("Unable to find $setterName on ${valueClass.name}")
            setter.isAccessible = true
            setter.invoke(valueObject, value)
        }

        return valueObject
    }

    private fun ensureHiddenApiAccess() {
        runCatching { HiddenApiBypass.addHiddenApiExemptions("") }
    }

    fun getKeystoreService(): Any? {
        return runCatching {
            val binder = lookupBinder() ?: return null
            val stubClass = loadClass("${CLASS_IKEYSTORE_SERVICE}\$Stub")
            val asInterface = stubClass.getMethod("asInterface", IBinder::class.java)
            asInterface.invoke(null, binder)
        }.getOrNull()
    }

    fun resolveSecurityLevel(service: Any, level: Int): Any? {
        return runCatching {
            val method = service.javaClass.methods.firstOrNull {
                it.name == "getSecurityLevel" && it.parameterTypes.size == 1
            } ?: throw NoSuchMethodException("Unable to find hidden getSecurityLevel(int) on ${service.javaClass.name}")
            method.isAccessible = true
            method.invoke(service, level)
        }.getOrNull()
    }

    private fun createPrivateKeystoreServiceProxy(
        rawBinder: IBinder,
        diagnosticsCollector: CapturedThrowableCollector,
        captureGenerateKeyReplies: Boolean,
    ): Any? {
        val serviceInterface = loadClass(CLASS_IKEYSTORE_SERVICE)
        val serviceProxyClass = loadClass("${CLASS_IKEYSTORE_SERVICE}\$Stub\$Proxy")
        val constructor = serviceProxyClass.getDeclaredConstructor(IBinder::class.java)
        constructor.isAccessible = true
        val stubProxy = constructor.newInstance(rawBinder)

        return Proxy.newProxyInstance(
            ClassLoader.getSystemClassLoader(),
            arrayOf(serviceInterface),
        ) { _, method, args ->
            invokeProxyMethod(
                target = stubProxy,
                method = method,
                args = args,
                mapper = { result ->
                    // service.getSecurityLevel() 返回的对象也必须包一层私有代理；否则 generateKey 这类深层 transact 会绕过会话级诊断和 reply capture。
                    // The object returned by service.getSecurityLevel() also needs a private proxy, or deeper transacts such as generateKey bypass session diagnostics and reply capture.
                    if (method.name == "getSecurityLevel" && result != null) {
                        createPrivateSecurityLevelProxy(
                            realSecurityLevel = result,
                            diagnosticsCollector = diagnosticsCollector,
                            captureGenerateKeyReplies = captureGenerateKeyReplies,
                        )
                    } else {
                        result
                    }
                },
                diagnosticsCollector = diagnosticsCollector,
                failurePhase = "service.${method.name}",
            )
        }
    }

    private fun createPrivateSecurityLevelProxy(
        realSecurityLevel: Any,
        diagnosticsCollector: CapturedThrowableCollector,
        captureGenerateKeyReplies: Boolean,
    ): Any {
        return runCatching {
            val securityLevelInterface = loadClass(CLASS_IKEYSTORE_SECURITY_LEVEL)
            val securityLevelProxyClass = loadClass("${CLASS_IKEYSTORE_SECURITY_LEVEL}\$Stub\$Proxy")
            val asBinderMethod = realSecurityLevel.javaClass.getMethod("asBinder")
            val rawBinder = asBinderMethod.invoke(realSecurityLevel) as IBinder

            val binderProxy = Proxy.newProxyInstance(
                ClassLoader.getSystemClassLoader(),
                arrayOf(IBinder::class.java),
            ) { _, method, args ->
                when (method.name) {
                    "queryLocalInterface" -> null
                    "transact" -> {
                        val transactionCode = args[0] as Int
                        val reply = args[2] as? Parcel
                        val success = rawBinder.transact(
                            transactionCode,
                            args[1] as Parcel,
                            reply,
                            args[3] as Int,
                        )
                        // generateKey 指纹检测依赖原始 reply bytes，所以只能在 transact 边界抓包，晚一步就只剩解包后的对象了。
                        // The generateKey fingerprint depends on raw reply bytes, so capture has to happen at the transact boundary before the parcel is decoded.
                        if (captureGenerateKeyReplies) {
                            captureGenerateKeyReplyFromTransact(
                                transactionCode = transactionCode,
                                reply = reply,
                                transactReturned = success,
                            )
                        }
                        success
                    }
                    else -> invokeProxyMethod(
                        rawBinder,
                        method,
                        args,
                        diagnosticsCollector = diagnosticsCollector,
                        failurePhase = "securityLevelBinder.${method.name}",
                    )
                }
            } as IBinder

            val constructor = securityLevelProxyClass.getDeclaredConstructor(IBinder::class.java)
            constructor.isAccessible = true
            val stubProxy = constructor.newInstance(binderProxy)
            Proxy.newProxyInstance(
                ClassLoader.getSystemClassLoader(),
                arrayOf(securityLevelInterface),
            ) { _, method, args ->
                if (method.name == "asBinder") {
                    binderProxy
                } else {
                    invokeProxyMethod(
                        stubProxy,
                        method,
                        args,
                        diagnosticsCollector = diagnosticsCollector,
                        failurePhase = "securityLevel.${method.name}",
                    )
                }
            }
        }.getOrElse { realSecurityLevel }
    }

    private fun invokeProxyMethod(
        target: Any,
        method: Method,
        args: Array<out Any?>?,
        mapper: ((Any?) -> Any?)? = null,
        diagnosticsCollector: CapturedThrowableCollector? = null,
        failurePhase: String? = null,
    ): Any? {
        return try {
            val result = method.invoke(target, *(args ?: emptyArray()))
            mapper?.invoke(result) ?: result
        } catch (throwable: InvocationTargetException) {
            val cause = throwable.cause ?: throwable
            if (diagnosticsCollector != null && failurePhase != null) {
                diagnosticsCollector.record(
                    phase = failurePhase,
                    summary = describeThrowable(cause),
                    throwable = cause,
                )
            }
            throw cause
        }
    }

    private fun captureReplySnapshot(reply: Parcel): Keystore2ReplySnapshot? {
        val rawBytes = runCatching { reply.marshall() }.getOrDefault(ByteArray(0))
        if (rawBytes.isEmpty() && reply.dataSize() == 0) {
            return null
        }
        reply.setDataPosition(0)
        val exceptionCode = if (reply.dataSize() >= 4) reply.readInt() else null
        val secondWord = if (reply.dataSize() >= 8) reply.readInt() else null
        val trailingInts = buildList {
            while (reply.dataPosition() + 4 <= reply.dataSize() && size < 4) {
                add(reply.readInt())
            }
        }
        reply.setDataPosition(0)
        return Keystore2ReplySnapshot(
            rawPrefix = rawReplyPrefix(rawBytes),
            exceptionCode = exceptionCode,
            secondWord = secondWord,
            trailingInts = trailingInts,
            dataSize = rawBytes.size,
        )
    }

    private fun captureGenerateKeyReplyFromTransact(
        transactionCode: Int,
        reply: Parcel?,
        transactReturned: Boolean,
    ) {
        val slot = generateKeyReplyCaptureSlot.get() ?: return
        if (transactionCode != generateKeyTransactionCode()) {
            return
        }
        if (slot.completed) {
            return
        }
        slot.transactionCode = transactionCode
        slot.transactReturned = transactReturned
        if (reply == null) {
            slot.failureReason = "generateKey transact completed without a reply parcel."
            slot.completed = true
            return
        }
        val rawReply = runCatching { reply.marshall() }.getOrElse { throwable ->
            slot.failureReason = throwable.message ?: "generateKey reply marshalling failed."
            slot.completed = true
            return
        }
        if (rawReply.isEmpty() && reply.dataSize() == 0) {
            slot.failureReason = "generateKey reply parcel was empty."
            slot.completed = true
            return
        }
        slot.rawReply = rawReply
        slot.rawPrefix = rawReplyPrefix(rawReply)
        slot.completed = true
    }

    private fun rawReplyPrefix(rawReply: ByteArray): String {
        return rawReply
            .take(MAX_REPLY_PREFIX_BYTES)
            .joinToString(" ") { "%02X".format(it.toInt() and 0xFF) }
    }

    private fun generateKeyTransactionCode(): Int {
        cachedGenerateKeyTransactionCode?.let { return it }
        val resolved = runCatching {
            val stubClass = loadClass("${CLASS_IKEYSTORE_SECURITY_LEVEL}\$Stub")
            stubClass.getField("TRANSACTION_generateKey").getInt(null)
        }.getOrDefault(TRANSACTION_GENERATE_KEY)
        cachedGenerateKeyTransactionCode = resolved
        return resolved
    }

    private fun setField(target: Any, name: String, value: Any?) {
        val field = target.javaClass.getDeclaredField(name)
        field.isAccessible = true
        field.set(target, value)
    }

    private fun getFieldValue(target: Any, name: String): Any? {
        return runCatching {
            val field = target.javaClass.getField(name)
            field.isAccessible = true
            field.get(target)
        }.recoverCatching {
            val field = target.javaClass.getDeclaredField(name)
            field.isAccessible = true
            field.get(target)
        }.getOrNull()
    }

    fun toObjectArray(value: Any?): Array<Any?> {
        if (value == null || !value.javaClass.isArray) {
            return emptyArray()
        }
        val length = java.lang.reflect.Array.getLength(value)
        return Array(length) { index -> java.lang.reflect.Array.get(value, index) }
    }

    private fun buildListEntriesArgs(
        parameterTypes: Array<Class<*>>,
        startPastAlias: String? = null,
    ): Array<Any?> {
        return parameterTypes.map { type ->
            when {
                type == Int::class.javaPrimitiveType || type == Int::class.java -> 0
                type == Long::class.javaPrimitiveType || type == Long::class.java -> -1L
                type == String::class.java -> startPastAlias
                type == Boolean::class.javaPrimitiveType || type == Boolean::class.java -> false
                else -> null
            }
        }.toTypedArray()
    }

    private fun findThrowable(
        throwable: Throwable,
        predicate: (Throwable) -> Boolean,
    ): Throwable? {
        var current: Throwable? = throwable
        while (current != null) {
            if (predicate(current)) {
                return current
            }
            current = current.cause
        }
        return null
    }

    private fun findRootCause(throwable: Throwable): Throwable {
        var current = throwable
        while (current.cause != null && current.cause !== current) {
            current = current.cause!!
        }
        return current
    }

    private fun loadClass(className: String): Class<*> {
        return try {
            Class.forName(className)
        } catch (primary: ClassNotFoundException) {
            try {
                ClassLoader.getSystemClassLoader().loadClass(className)
            } catch (secondary: ClassNotFoundException) {
                try {
                    HiddenApiBypass.invoke(Class::class.java, null, "forName", className) as Class<*>
                } catch (throwable: Throwable) {
                    throw ClassNotFoundException("Unable to load hidden class $className", throwable)
                }
            }
        }
    }

    companion object {
        const val SERVICE_NAME = "android.system.keystore2.IKeystoreService/default"
        const val INTERFACE_DESCRIPTOR = "android.system.keystore2.IKeystoreService"
        const val TRANSACTION_GET_KEY_ENTRY = 2
        const val TRANSACTION_GENERATE_KEY = 2
        const val SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1
        const val SECURITY_LEVEL_STRONGBOX = 2
        const val DEFAULT_ALIAS_PREFIX = "Budin_Key_DuckTiming"
        const val DEFAULT_GENERATE_MODE_ALIAS_PREFIX = "Budin_Key_DuckGenerateMode"
        const val DOMAIN_KEY_ID_FALLBACK = 4

        private const val CLASS_IKEYSTORE_SERVICE = "android.system.keystore2.IKeystoreService"
        private const val CLASS_IKEYSTORE_SECURITY_LEVEL = "android.system.keystore2.IKeystoreSecurityLevel"
        private const val CLASS_KEY_DESCRIPTOR = "android.system.keystore2.KeyDescriptor"
        private const val CLASS_KEY_PARAMETER = "android.hardware.security.keymint.KeyParameter"
        private const val CLASS_KEY_PARAMETER_VALUE = "android.hardware.security.keymint.KeyParameterValue"
        private const val MAX_REPLY_PREFIX_BYTES = 32

        @Volatile
        private var cachedGenerateKeyTransactionCode: Int? = null
        private val generateKeyReplyCaptureSlot = ThreadLocal<GenerateKeyReplyCaptureSlot?>()
    }
}

private data class HiddenMethodInvocation(
    val target: Any,
    val method: Method,
    val args: Array<Any?>,
)

private data class GenerateKeyReplyCaptureSnapshot(
    val rawReply: ByteArray? = null,
    val rawPrefix: String? = null,
    val transactionCode: Int? = null,
    val transactReturned: Boolean? = null,
    val throwable: Throwable? = null,
    val failureReason: String? = null,
)

private class GenerateKeyReplyCaptureSlot {
    var rawReply: ByteArray? = null
    var rawPrefix: String? = null
    var transactionCode: Int? = null
    var transactReturned: Boolean? = null
    var failureReason: String? = null
    var completed: Boolean = false

    fun toSnapshot(
        throwable: Throwable? = null,
        defaultFailureReason: String,
    ): GenerateKeyReplyCaptureSnapshot {
        return GenerateKeyReplyCaptureSnapshot(
            rawReply = rawReply,
            rawPrefix = rawPrefix,
            transactionCode = transactionCode,
            transactReturned = transactReturned,
            throwable = throwable,
            failureReason = failureReason ?: if (rawReply == null) defaultFailureReason else null,
        )
    }
}

data class GenerateKeyReplyCaptureResult(
    val available: Boolean,
    val rawReply: ByteArray? = null,
    val rawPrefix: String? = null,
    val detail: String,
)

data class Keystore2BinderRequest(
    val interfaceDescriptor: String,
    val transactionCode: Int,
    val alias: String,
    val writeTo: (Parcel) -> Unit,
)

data class Keystore2ReplySnapshot(
    val rawPrefix: String? = null,
    val exceptionCode: Int? = null,
    val secondWord: Int? = null,
    val trailingInts: List<Int> = emptyList(),
    val dataSize: Int = 0,
)

data class BinderTransactionResult(
    val success: Boolean,
    val replySnapshot: Keystore2ReplySnapshot? = null,
    val replyFailureReason: String? = null,
    val throwable: Throwable? = null,
)

data class Keystore2PrivateSessionResult(
    val session: Keystore2PrivateSession? = null,
    val failureReason: String? = null,
    val capturedFailures: List<CapturedThrowableRecord> = emptyList(),
)

data class Keystore2PrivateSession(
    val binder: IBinder,
    val service: Any,
    val securityLevel: Any,
    val proxyInstalled: Boolean,
    val serviceProxyActive: Boolean,
    val securityLevelProxyActive: Boolean,
    val diagnosticsCollector: CapturedThrowableCollector = CapturedThrowableCollector(),
)

data class TimingKeyAliases(
    val aliasPrefix: String,
    val attestedAlias: String,
    val nonAttestedAlias: String,
    val attestKeyAlias: String,
)

data class CapturedThrowableRecord(
    val phase: String,
    val summary: String,
    val stackTrace: String,
    val fingerprint: String,
    val occurrenceCount: Int = 1,
)

class CapturedThrowableCollector {
    private val records = LinkedHashMap<String, CapturedThrowableRecord>()

    fun record(
        phase: String,
        summary: String,
        throwable: Throwable,
    ) {
        // 这里按摘要+堆栈去重，保留第一次出现的位置，并累计次数；这样复制出来的 payload 既能静态审查，也不会被重复异常淹没。
        // De-duplicate by summary + stack, keep the first occurrence phase, and accumulate counts so copied payloads stay reviewable instead of noisy.
        val fingerprint = capturedThrowableFingerprint(summary, throwable)
        val current = records[fingerprint]
        records[fingerprint] = if (current == null) {
            CapturedThrowableRecord(
                phase = phase,
                summary = summary,
                stackTrace = throwable.stackTraceToString().trim(),
                fingerprint = fingerprint,
            )
        } else {
            current.copy(occurrenceCount = current.occurrenceCount + 1)
        }
    }

    fun isEmpty(): Boolean = records.isEmpty()

    fun snapshot(): List<CapturedThrowableRecord> = records.values.toList()
}

internal fun keyParameterSetterNameForTag(tag: Int): String {
    val type = tag and 0xf0000000.toInt()
    val tagId = tag and 0x0fffffff
    return when (type) {
        0x10000000, 0x20000000 -> when (tagId) {
            1 -> "setKeyPurpose"
            2 -> "setAlgorithm"
            4 -> "setBlockMode"
            5 -> "setDigest"
            6 -> "setPaddingMode"
            10 -> "setEcCurve"
            304 -> "setSecurityLevel"
            702 -> "setOrigin"
            else -> "setInteger"
        }
        0x30000000, 0x40000000 -> "setInteger"
        0x50000000, 0xA0000000.toInt() -> "setLongInteger"
        0x60000000 -> "setDateTime"
        0x70000000 -> "setBoolValue"
        0x80000000.toInt(), 0x90000000.toInt() -> "setBlob"
        else -> "setInteger"
    }
}

internal fun keyParameterParameterType(value: Any): Class<*> {
    return when (value) {
        is Int -> Int::class.javaPrimitiveType ?: Int::class.java
        is Long -> Long::class.javaPrimitiveType ?: Long::class.java
        is Boolean -> Boolean::class.javaPrimitiveType ?: Boolean::class.java
        else -> value.javaClass
    }
}

internal fun capturedThrowableFingerprint(
    summary: String,
    throwable: Throwable,
): String {
    val root = generateSequence(throwable) { it.cause }.last()
    val frames = root.stackTrace
        .take(6)
        .joinToString("|") { frame -> "${frame.className}.${frame.methodName}:${frame.lineNumber}" }
    return "${root.javaClass.name}|$summary|$frames"
}

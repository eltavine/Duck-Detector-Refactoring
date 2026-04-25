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
import org.lsposed.hiddenapibypass.HiddenApiBypass
import java.lang.reflect.Field
import java.lang.reflect.InvocationHandler
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import java.lang.reflect.Proxy
import java.util.concurrent.ConcurrentHashMap

object KeystoreBinderCaptureHook {

    private const val KEYSTORE2_SERVICE_NAME = "android.system.keystore2.IKeystoreService/default"
    private const val KEYSTORE2_INTERFACE = "android.system.keystore2.IKeystoreService"
    private const val KEYSTORE2_SECURITY_LEVEL = "android.system.keystore2.IKeystoreSecurityLevel"
    private const val LEGACY_SERVICE_NAME = "android.security.keystore"

    private val generateKeyLeafCertsByAlias = ConcurrentHashMap<String, ByteArray>()
    private val generateKeyChainBlobsByAlias = ConcurrentHashMap<String, ByteArray>()
    private val getKeyEntryLeafCertsByAlias = ConcurrentHashMap<String, ByteArray>()
    private val getKeyEntryChainBlobsByAlias = ConcurrentHashMap<String, ByteArray>()
    private val legacyGetByName = ConcurrentHashMap<String, ByteArray>()

    private val lock = Any()

    @Volatile
    private var hookInstalled = false

    private var originalKeystore2Binder: IBinder? = null
    private var originalLegacyBinder: IBinder? = null

    fun installHook(): Boolean = synchronized(lock) {
        resetCaptures()
        restoreLocked()
        ensureHiddenApiAccess()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && installKeystore2HookLocked()) {
            hookInstalled = true
            return@synchronized true
        }

        if (installLegacyHookLocked()) {
            hookInstalled = true
            return@synchronized true
        }

        false
    }

    fun restore() = synchronized(lock) {
        restoreLocked()
    }

    fun isHookInstalled(): Boolean = hookInstalled

    fun getGenerateKeyLeafCertificate(alias: String): ByteArray? = generateKeyLeafCertsByAlias[alias]

    fun getGenerateKeyCertificateChainBlob(alias: String): ByteArray? = generateKeyChainBlobsByAlias[alias]

    fun getKeyEntryLeafCertificate(alias: String): ByteArray? = getKeyEntryLeafCertsByAlias[alias]

    fun getKeyEntryCertificateChainBlob(alias: String): ByteArray? = getKeyEntryChainBlobsByAlias[alias]

    fun getLegacyKeystoreBlob(name: String): ByteArray? = legacyGetByName[name]

    fun resetCaptures() {
        generateKeyLeafCertsByAlias.clear()
        generateKeyChainBlobsByAlias.clear()
        getKeyEntryLeafCertsByAlias.clear()
        getKeyEntryChainBlobsByAlias.clear()
        legacyGetByName.clear()
    }

    private fun installKeystore2HookLocked(): Boolean {
        return runCatching {
            val serviceManager = Class.forName("android.os.ServiceManager")
            val cache = getServiceManagerCache(serviceManager)
            val getService = serviceManager.getMethod("getService", String::class.java)
            val rawBinder = getService.invoke(null, KEYSTORE2_SERVICE_NAME) as? IBinder ?: return false
            originalKeystore2Binder = rawBinder

            val serviceInterface = Class.forName(KEYSTORE2_INTERFACE)
            val proxyClass = Class.forName("${KEYSTORE2_INTERFACE}\$Stub\$Proxy")
            val constructor = proxyClass.getDeclaredConstructor(IBinder::class.java).apply {
                isAccessible = true
            }
            val realService = constructor.newInstance(rawBinder)
            val proxyService = Proxy.newProxyInstance(
                serviceInterface.classLoader ?: ClassLoader.getSystemClassLoader(),
                arrayOf(serviceInterface),
                Keystore2InvocationHandler(realService),
            )
            val proxyBinder = Proxy.newProxyInstance(
                IBinder::class.java.classLoader ?: ClassLoader.getSystemClassLoader(),
                arrayOf(IBinder::class.java),
                BinderProxyHandler(rawBinder, proxyService, KEYSTORE2_INTERFACE),
            ) as IBinder
            cache[KEYSTORE2_SERVICE_NAME] = proxyBinder
            true
        }.getOrDefault(false)
    }

    private fun installLegacyHookLocked(): Boolean {
        return runCatching {
            val serviceManager = Class.forName("android.os.ServiceManager")
            val cache = getServiceManagerCache(serviceManager)
            val getService = serviceManager.getMethod("getService", String::class.java)
            val rawBinder = getService.invoke(null, LEGACY_SERVICE_NAME) as? IBinder ?: return false
            originalLegacyBinder = rawBinder

            val interfaceName = resolveLegacyInterfaceName()
            val serviceInterface = Class.forName(interfaceName)
            val proxyClass = Class.forName("$interfaceName\$Stub\$Proxy")
            val constructor = proxyClass.getDeclaredConstructor(IBinder::class.java).apply {
                isAccessible = true
            }
            val realService = constructor.newInstance(rawBinder)
            val proxyService = Proxy.newProxyInstance(
                serviceInterface.classLoader ?: ClassLoader.getSystemClassLoader(),
                arrayOf(serviceInterface),
                LegacyKeystoreInvocationHandler(realService),
            )
            val proxyBinder = Proxy.newProxyInstance(
                IBinder::class.java.classLoader ?: ClassLoader.getSystemClassLoader(),
                arrayOf(IBinder::class.java),
                BinderProxyHandler(rawBinder, proxyService, interfaceName),
            ) as IBinder
            cache[LEGACY_SERVICE_NAME] = proxyBinder
            true
        }.getOrDefault(false)
    }

    @Suppress("UNCHECKED_CAST")
    private fun getServiceManagerCache(serviceManagerClass: Class<*>): MutableMap<String, IBinder> {
        val cacheField = serviceManagerClass.getDeclaredField("sCache").apply { isAccessible = true }
        return cacheField.get(null) as MutableMap<String, IBinder>
    }

    private fun resolveLegacyInterfaceName(): String {
        return runCatching {
            Class.forName("android.security.keystore.IKeystoreService")
            "android.security.keystore.IKeystoreService"
        }.getOrDefault("android.security.IKeystoreService")
    }

    private fun restoreLocked() {
        runCatching {
            val serviceManager = Class.forName("android.os.ServiceManager")
            val cache = getServiceManagerCache(serviceManager)
            originalKeystore2Binder?.let { cache[KEYSTORE2_SERVICE_NAME] = it }
            originalLegacyBinder?.let { cache[LEGACY_SERVICE_NAME] = it }
        }
        originalKeystore2Binder = null
        originalLegacyBinder = null
        hookInstalled = false
    }

    private fun ensureHiddenApiAccess() {
        runCatching { HiddenApiBypass.addHiddenApiExemptions("") }
    }

    private class Keystore2InvocationHandler(
        private val realService: Any,
    ) : InvocationHandler {
        override fun invoke(proxy: Any?, method: Method, args: Array<out Any?>?): Any? {
            val result = invokeTarget(realService, method, args)
            return when (method.name) {
                "getSecurityLevel" -> result?.let(::wrapKeystore2SecurityLevelIfPossible) ?: result
                "getKeyEntry" -> {
                    val alias = tryExtractAlias(args, 0)
                    alias?.let { captureGetKeyEntry(it, result) }
                    result
                }

                "generateKey" -> {
                    val alias = tryExtractAlias(args, 0)
                    alias?.let { captureGenerateKey(it, result) }
                    result
                }

                else -> result
            }
        }
    }

    private class KeyMintSecurityLevelInvocationHandler(
        private val realService: Any,
    ) : InvocationHandler {
        override fun invoke(proxy: Any?, method: Method, args: Array<out Any?>?): Any? {
            val result = invokeTarget(realService, method, args)
            if (method.name == "generateKey") {
                tryExtractAlias(args, 0)?.let { alias ->
                    captureGenerateKey(alias, result)
                }
            }
            return result
        }
    }

    private class LegacyKeystoreInvocationHandler(
        private val realService: Any,
    ) : InvocationHandler {
        override fun invoke(proxy: Any?, method: Method, args: Array<out Any?>?): Any? {
            val result = invokeTarget(realService, method, args)
            if (method.name == "get" && result is ByteArray && args?.getOrNull(0) is String) {
                legacyGetByName[args[0] as String] = result
            }
            return result
        }
    }

    private class BinderProxyHandler(
        private val realBinder: IBinder,
        private val proxyService: Any,
        private val interfaceDescriptor: String,
    ) : InvocationHandler {
        override fun invoke(proxy: Any?, method: Method, args: Array<out Any?>?): Any? {
            return when (method.name) {
                "queryLocalInterface" -> proxyService
                "getInterfaceDescriptor" -> interfaceDescriptor
                else -> invokeTarget(realBinder, method, args)
            }
        }
    }

    private fun wrapKeystore2SecurityLevelIfPossible(securityLevel: Any): Any? {
        return runCatching {
            val securityLevelInterface = Class.forName(KEYSTORE2_SECURITY_LEVEL)
            if (!securityLevelInterface.isInstance(securityLevel)) {
                return null
            }
            Proxy.newProxyInstance(
                securityLevelInterface.classLoader ?: ClassLoader.getSystemClassLoader(),
                arrayOf(securityLevelInterface),
                KeyMintSecurityLevelInvocationHandler(securityLevel),
            )
        }.getOrNull()
    }

    private fun captureGenerateKey(alias: String, result: Any?) {
        tryGetByteArrayField(result, "certificate")?.let {
            generateKeyLeafCertsByAlias[alias] = it
        }
        tryGetByteArrayField(result, "certificateChain")?.let {
            generateKeyChainBlobsByAlias[alias] = it
        }
    }

    private fun captureGetKeyEntry(alias: String, result: Any?) {
        val metadata = tryGetFieldValue(result, "metadata")
        tryGetByteArrayField(metadata, "certificate")?.let {
            getKeyEntryLeafCertsByAlias[alias] = it
        }
        tryGetByteArrayField(metadata, "certificateChain")?.let {
            getKeyEntryChainBlobsByAlias[alias] = it
        }
    }

    private fun tryExtractAlias(args: Array<out Any?>?, index: Int): String? {
        val descriptor = args?.getOrNull(index) ?: return null
        return tryGetFieldValue(descriptor, "alias") as? String
    }

    private fun tryGetByteArrayField(target: Any?, fieldName: String): ByteArray? {
        return tryGetFieldValue(target, fieldName) as? ByteArray
    }

    private fun tryGetFieldValue(target: Any?, fieldName: String): Any? {
        if (target == null) {
            return null
        }
        return readField(target.javaClass, target, fieldName)
    }

    private fun readField(type: Class<*>, target: Any, fieldName: String): Any? {
        return runCatching {
            val field = findField(type, fieldName)
            field.isAccessible = true
            field.get(target)
        }.getOrNull()
    }

    private fun findField(type: Class<*>, fieldName: String): Field {
        var current: Class<*>? = type
        while (current != null) {
            runCatching { return current.getDeclaredField(fieldName) }
            current = current.superclass
        }
        throw NoSuchFieldException(fieldName)
    }

    private fun invokeTarget(target: Any, method: Method, args: Array<out Any?>?): Any? {
        return try {
            method.invoke(target, *(args ?: emptyArray()))
        } catch (throwable: InvocationTargetException) {
            throw throwable.cause ?: throwable
        }
    }
}

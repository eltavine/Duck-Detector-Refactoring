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

import android.content.Context
import android.os.Build
import android.security.keystore.KeyStoreManager
import java.security.cert.X509Certificate
import org.lsposed.hiddenapibypass.HiddenApiBypass

internal interface KeyStoreGrantJavaApi {
    val stageLabel: String

    fun grantKeyAccess(alias: String, uid: Int): Long

    fun getGrantedCertificateChainFromId(grantId: Long): List<X509Certificate>

    fun revokeKeyAccess(alias: String, uid: Int)
}

internal object KeyStoreGrantJavaApis {
    fun publicApi(context: Context): KeyStoreGrantJavaApiResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.BAKLAVA) {
            return KeyStoreGrantJavaApiResult.unavailable(
                stage = "Public",
                detail = "Public: unsupported (Android < 16).",
            )
        }
        return runCatching {
            context.applicationContext.getSystemService(KeyStoreManager::class.java)
                ?.let(::PublicKeyStoreGrantJavaApi)
        }.fold(
            onSuccess = { api ->
                api?.let { KeyStoreGrantJavaApiResult.available(it) }
                    ?: KeyStoreGrantJavaApiResult.unavailable(
                        stage = "Public",
                        detail = "Public: unavailable (KeyStoreManager grant API missing).",
                    )
            },
            onFailure = { throwable ->
                KeyStoreGrantJavaApiResult.unavailable(
                    stage = "Public",
                    detail = "Public: unavailable (${GrantThrowableFormatter.describe(throwable)}).",
                    throwable = throwable,
                )
            },
        )
    }

    fun hiddenApi(context: Context): KeyStoreGrantJavaApiResult {
        return runCatching {
            HiddenApiBypass.addHiddenApiExemptions("")
            val managerClass = loadClass(CLASS_KEYSTORE_MANAGER)
            val manager = context.applicationContext.getSystemService(managerClass)
                ?: managerClass.getDeclaredMethod("getInstance")
                    .also { it.isAccessible = true }
                    .invoke(null)
                ?: return@runCatching null
            HiddenKeyStoreGrantJavaApi(managerClass, manager)
        }.fold(
            onSuccess = { api ->
                api?.let { KeyStoreGrantJavaApiResult.available(it) }
                    ?: KeyStoreGrantJavaApiResult.unavailable(
                        stage = "Hidden",
                        detail = "Hidden: unavailable (KeyStoreManager service missing).",
                    )
            },
            onFailure = { throwable ->
                KeyStoreGrantJavaApiResult.unavailable(
                    stage = "Hidden",
                    detail = "Hidden: unavailable (${GrantThrowableFormatter.describe(throwable)}).",
                    throwable = throwable,
                )
            },
        )
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

    private const val CLASS_KEYSTORE_MANAGER = "android.security.keystore.KeyStoreManager"
}

internal data class KeyStoreGrantJavaApiResult(
    val available: Boolean,
    val api: KeyStoreGrantJavaApi? = null,
    val stage: String,
    val detail: String,
    val throwable: Throwable? = null,
) {
    companion object {
        fun available(api: KeyStoreGrantJavaApi): KeyStoreGrantJavaApiResult {
            return KeyStoreGrantJavaApiResult(
                available = true,
                api = api,
                stage = api.stageLabel,
                detail = "${api.stageLabel}: available.",
            )
        }

        fun unavailable(
            stage: String,
            detail: String,
            throwable: Throwable? = null,
        ): KeyStoreGrantJavaApiResult {
            return KeyStoreGrantJavaApiResult(
                available = false,
                stage = stage,
                detail = detail,
                throwable = throwable,
            )
        }
    }
}

private class PublicKeyStoreGrantJavaApi(
    private val manager: KeyStoreManager,
) : KeyStoreGrantJavaApi {
    override val stageLabel: String = "Public"

    override fun grantKeyAccess(alias: String, uid: Int): Long {
        return manager.grantKeyAccess(alias, uid)
    }

    override fun getGrantedCertificateChainFromId(grantId: Long): List<X509Certificate> {
        return manager.getGrantedCertificateChainFromId(grantId)
            .filterIsInstance<X509Certificate>()
    }

    override fun revokeKeyAccess(alias: String, uid: Int) {
        manager.revokeKeyAccess(alias, uid)
    }
}

private class HiddenKeyStoreGrantJavaApi(
    private val managerClass: Class<*>,
    private val manager: Any,
) : KeyStoreGrantJavaApi {
    override val stageLabel: String = "Hidden"

    override fun grantKeyAccess(alias: String, uid: Int): Long {
        return (invokeHidden(
            name = "grantKeyAccess",
            parameterTypes = arrayOf(String::class.java, Int::class.javaPrimitiveType!!),
            args = arrayOf(alias, uid),
        ) as Number).toLong()
    }

    override fun getGrantedCertificateChainFromId(grantId: Long): List<X509Certificate> {
        val raw = invokeHidden(
            name = "getGrantedCertificateChainFromId",
            parameterTypes = arrayOf(Long::class.javaPrimitiveType!!),
            args = arrayOf(grantId),
        )
        return raw.toX509CertificateList()
    }

    override fun revokeKeyAccess(alias: String, uid: Int) {
        invokeHidden(
            name = "revokeKeyAccess",
            parameterTypes = arrayOf(String::class.java, Int::class.javaPrimitiveType!!),
            args = arrayOf(alias, uid),
        )
    }

    private fun invokeHidden(
        name: String,
        parameterTypes: Array<Class<*>>,
        args: Array<Any?>,
    ): Any? {
        return try {
            val method = managerClass.getDeclaredMethod(name, *parameterTypes)
            method.isAccessible = true
            method.invoke(manager, *args)
        } catch (throwable: java.lang.reflect.InvocationTargetException) {
            throw throwable.cause ?: throwable
        } catch (throwable: Throwable) {
            // Some Android releases keep these methods hidden from normal reflection even after class
            // loading succeeds; HiddenApiBypass.invoke is the final Java-layer path before we give up.
            // 部分 Android 版本即使类加载成功，也会把这些方法挡在普通反射之外；HiddenApiBypass.invoke 是放弃前最后一层 Java 路径。
            try {
                HiddenApiBypass.invoke(managerClass, manager, name, *args)
            } catch (bypassThrowable: java.lang.reflect.InvocationTargetException) {
                throw bypassThrowable.cause ?: bypassThrowable
            }
        }
    }
}

private fun Any?.toX509CertificateList(): List<X509Certificate> {
    return when (this) {
        is Collection<*> -> filterIsInstance<X509Certificate>()
        is Array<*> -> filterIsInstance<X509Certificate>()
        else -> emptyList()
    }
}

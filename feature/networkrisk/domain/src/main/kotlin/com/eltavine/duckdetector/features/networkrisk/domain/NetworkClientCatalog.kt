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

package com.eltavine.duckdetector.features.networkrisk.domain

/** Pins identify only the sampled upstream GitHub release channel; see EVIDENCE.md. */
data class NetworkClientDefinition(
    val name: String,
    val packageName: String,
    val releaseCertificateSha256: String? = null,
)

object NetworkClientCatalog {
    val entries: List<NetworkClientDefinition> = listOf(
        NetworkClientDefinition("Clash Meta for Android", "com.github.metacubex.clash.meta", "5f5571af767fe0f611292aa088b445a05f725fb8262fb80a13b69e4d809ae1f1"),
        NetworkClientDefinition("Clash Meta for Android (alpha)", "com.github.metacubex.clash.alpha"),
        NetworkClientDefinition("Clash Meta for Android (suffix-free)", "com.github.metacubex.clash"),
        NetworkClientDefinition("Surfboard", "com.getsurfboard", "62c9bb5f2d1804c61c1026a3c98e45c697a076542ec784b736438eb8bba221d4"),
        NetworkClientDefinition("FlClash", "com.follow.clash", "2859e236b6c1c6073773752678c52e8e902a9503ae9beed6729ca999c376841c"),
        NetworkClientDefinition("sing-box for Android", "io.nekohasekai.sfa", "32250a4b5f3a6733df57a3b9ec16c38d2c7fc5f2f693a9636f8f7b3be3549641"),
        NetworkClientDefinition("v2rayNG", "com.v2ray.ang", "b7dc883e7678d6c618569e48a1c8c267a134a75f8bcb763510c8bffb3b90b077"),
        NetworkClientDefinition("v2rayNG (F-Droid flavor)", "com.v2ray.ang.fdroid"),
        NetworkClientDefinition("NekoBox", "moe.nb4a", "35762758ce86a6ec297d9ccac689469bc43b9fed8ae1b27f100a86bbac00a055"),
        NetworkClientDefinition("Hiddify", "app.hiddify.com", "454bf1f622d0fd5ebf93d4ce51fe5d4a93083b710bf2a01480cd570254c73d92"),
    )
}

fun NetworkClientDefinition.verifyCurrentSigners(currentSigners: Set<String>): ClientIdentity =
    if (releaseCertificateSha256 != null && currentSigners == setOf(releaseCertificateSha256)) {
        ClientIdentity.SIGNATURE_VERIFIED
    } else ClientIdentity.IDENTITY_UNVERIFIED

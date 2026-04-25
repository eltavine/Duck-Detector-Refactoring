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

package com.eltavine.duckdetector.features.dangerousapps.data.rules

import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppCategory
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppTarget

object DangerousAppsCatalog {

    val targets: List<DangerousAppTarget> = buildList {
        addCategory(
            DangerousAppCategory.HOOK_FRAMEWORK,
            pkg("org.lsposed.manager", "LSPosed Manager"),
            pkg("org.lsposed.lspatch", "LSPatch"),
            pkg("de.robv.android.xposed.installer", "Xposed Installer"),
            pkg("io.github.vvb2060.magisk", "Magisk alpha"),
            pkg("com.topjohnwu.magisk", "Magisk"),
            pkg("me.weishu.exp", "TaiChi"),
            pkg("me.simpleHook", "SimpleHook"),
            pkg("top.hookvip.pro", "HookVip Pro"),
            pkg("Hook.JiuWu.Xp", "JiuWu Hook"),
            pkg("com.bug.hookvip", "HookVip"),
            pkg("lin.xposed", "Lin Xposed"),
        )
        addCategory(
            DangerousAppCategory.APP_HIDE_TOOL,
            pkg("com.tsng.hidemyapplist", "Hide My Applist"),
            pkg("com.tsng.pzyhrx.hma", "HMA"),
            pkg("com.topmiaohan.hidebllist", "Hide Blacklist"),
            pkg("zako.zako.zako", "Zako Hide"),
        )
        addCategory(
            DangerousAppCategory.ROOT_TOOL,
            pkg("eu.chainfire.supersu", "SuperSU"),
            pkg("com.noshufou.android.su", "Superuser"),
            pkg("com.koushikdutta.superuser", "Superuser"),
            pkg("com.thirdparty.superuser", "Superuser"),
            pkg("com.yellowes.su", "SU"),
            pkg("com.kingroot.kinguser", "KingRoot"),
            pkg("com.kingo.root", "KingoRoot"),
            pkg("com.smedialink.oneclickroot", "OneClickRoot"),
            pkg("com.rifsxd.ksunext", "KSU Next"),
            pkg("io.github.a13e300.ksuwebui", "KSU WebUI"),
            pkg("com.sukisu.ultra", "SuKiSu Ultra"),
            pkg("com.resukisu.resukisu", "ReSukisu"),
        )
        addCategory(
            DangerousAppCategory.LOCATION_SPOOF,
            pkg("com.lerist.fakelocation", "Fake Location"),
            pkg("com.zhufucyd.motion_emulator", "Motion Emulator"),
        )
        addCategory(
            DangerousAppCategory.MOD_TOOL,
            pkg("com.cshlolss.vipkill", "VIP Kill"),
            pkg("com.modify.installer", "Modify Installer"),
            pkg("lucky.patcher", "Lucky Patcher"),
            pkg("com.chelpus.lackypatch", "Lucky Patcher"),
            pkg("com.android.vending.billing.InAppBillingService.LUCK", "Lucky Patcher"),
            pkg("ru.maximoff.apktool", "APKTool"),
            pkg("bin.mt.termex", "MT Manager"),
        )
        addCategory(
            DangerousAppCategory.CHAT_HOOK,
            pkg("io.github.qauxv", "QAuxiliary"),
            pkg("com.fkzhang.wechatxposed", "WeChat Xposed"),
            pkg("me.iacn.biliroaming", "BiliRoaming"),
            pkg("com.padi.hook.hookqq", "HookQQ"),
            pkg("top.sacz.timtool", "TIM Tool"),
        )
        addCategory(
            DangerousAppCategory.SYSTEM_MODIFICATION,
            pkg("com.sevtinge.hyperceiler", "HyperCeiler"),
            pkg("github.tornaco.android.thanos", "Thanox"),
            pkg("tornaco.apps.shortx", "ShortX"),
            pkg("com.omarea.vtools", "Scene"),
            pkg("name.monwf.customiuizer", "Customiuizer"),
            pkg("com.coderstory.toolkit", "Codestore Toolkit"),
        )
        addCategory(
            DangerousAppCategory.DEVICE_ID_MODIFICATION,
            pkg("com.silverlab.app.deviceidchanger.free", "Device ID Changer"),
            pkg("com.houvven.guise", "Guise"),
            pkg("com.houvven.impad", "IMPad"),
        )
        addCategory(
            DangerousAppCategory.PRIVACY_BYPASS,
            pkg("cn.geektang.privacyspace", "Privacy Space"),
            pkg("moe.shizuku.privileged.api", "Shizuku"),
            pkg("me.gm.cleaner", "Storage Isolation"),
            pkg("moe.shizuku.redirectstorage", "Storage Redirect"),
        )
        addCategory(
            DangerousAppCategory.BACKGROUND_CONTROL,
            pkg("nep.timeline.freezer", "Freezer"),
            pkg("cn.myflv.noactive", "NoActive"),
            pkg("web1n.stopapp", "StopApp"),
        )
        addCategory(
            DangerousAppCategory.TERMINAL_DEV,
            pkg("com.termux", "Termux"),
            pkg("com.didjdk.adbhelper", "ADB Helper"),
        )
        addCategory(
            DangerousAppCategory.MISC,
            pkg("me.bingyue.IceCore", "IceCore"),
            pkg("o.dyoo", "Dyoo"),
            pkg("com.demo.serendipity", "Serendipity"),
            pkg("me.teble.xposed.autodaily", "AutoDaily"),
            pkg("moe.fuqiuluo.portal", "Portal"),
            pkg("com.github.tianma8023.xposed.smscode", "XposedSmsCode"),
            pkg("xzr.hkf", "HKF"),
            pkg("xzr.konabess", "Konabess"),
            pkg("com.xayah.databackup.foss", "DataBackup"),
            pkg("com.byyoung.setting", "ByYoung Setting"),
            pkg("com.junge.algorithmAidePro", "Algorithm Aide Pro"),
            pkg("tmgp.atlas.toolbox", "Atlas Toolbox"),
            pkg("com.wn.app.np", "NP App"),
            pkg("top.bienvenido.saas.i18n", "Saas i18n"),
            pkg("com.syyf.quickpay", "QuickPay"),
            pkg("tornaco.apps.shortx.ext", "ShortX Ext"),
            pkg("com.mio.kitchen", "Mio Kitchen"),
            pkg("eu.faircode.xlua", "XLua"),
            pkg("com.dna.tools", "DNA Tools"),
            pkg("cn.myflv.monitor.noactive", "NoActive Monitor"),
            pkg("com.yuanwofei.cardemulator.pro", "Card Emulator Pro"),
            pkg("com.suqi8.oshin", "Oshin"),
            pkg("me.hd.wauxv", "Wauxv"),
            pkg("have.fun", "Have Fun"),
            pkg("miko.client", "Miko Client"),
            pkg("com.kooritea.fcmfix", "FCM Fix"),
            pkg("com.twifucker.hachidori", "Twifucker"),
            pkg("com.luckyzyx.luckytool", "LuckyTool"),
            pkg("cn.lyric.getter", "Lyric Getter"),
            pkg("com.parallelc.micts", "MICTS"),
            pkg("me.plusne", "Plusne"),
            pkg("com.hchen.appretention", "App Retention"),
            pkg("com.hchen.switchfreeform", "Switch Freeform"),
            pkg("cn.aodlyric.xiaowine", "XiaoWine Lyric"),
            pkg("nep.timeline.re_telegram", "RE Telegram"),
            pkg("com.fuck.android.rimet", "Fuck Rimet"),
            pkg("cn.kwaiching.hook", "Kwai Hook"),
            pkg("cn.android.x", "Android X"),
            pkg("cc.aoeiuv020.iamnotdisabled.hook", "IAmNotDisabled"),
            pkg("vn.kwaiching.tao", "Kwai Tao"),
            pkg("com.nnnen.plusne", "Plusne"),
            pkg("one.yufz.hmspush", "HMS Push"),
            pkg("cn.fuckhome.xiaowine", "XiaoWine"),
            pkg("com.fankes.tsbattery", "TSBattery"),
            pkg("com.rkg.IAMRKG", "IAMRKG"),
            pkg("com.ddm.qute", "Qute"),
            pkg("kk.dk.anqu", "Anqu"),
            pkg("com.qq.qcxm", "QQ Module"),
            pkg("com.wei.vip", "Wei VIP"),
            pkg("dknb.con", "DKNB"),
            pkg("dknb.coo8", "DKNB"),
            pkg("com.tencent.jingshi", "Jingshi"),
            pkg("com.tencent.JYNB", "JYNB"),
            pkg("com.apocalua.run", "Apocalua Run"),
            pkg("io.github.Retmon403.oppotheme", "Oppo Theme"),
            pkg("com.fankes.enforcehighrefreshrate", "High Refresh Rate"),
            pkg("es.chiteroman.bootloaderspoofer", "Bootloader Spoofer"),
            pkg("com.hchai.rescueplan", "Rescue Plan"),
        )
    }

    val targetByPackage: Map<String, DangerousAppTarget> = targets.associateBy { it.packageName }

    val specialPathDetection: Map<String, String> = linkedMapOf(
        "/dev/cpuset/scene-daemon" to "com.omarea.vtools",
        "/dev/memcg/scene_active" to "com.omarea.vtools",
        "/dev/memcg/scene_idle" to "com.omarea.vtools",
        "/dev/scene" to "com.omarea.vtools",
        "/sdcard/MT2" to "bin.mt.termex",
        "/sdcard/NP" to "com.wn.app.np",
        "/sdcard/xinhao" to "com.termux",
        "/sdcard/Download/advanced/" to "com.byyoung.setting",
        "/sdcard/.OShin" to "com.suqi8.oshin",
    )

    val excludedPathsForHmaInference: Set<String> = setOf(
        "/sdcard/MT2",
        "/sdcard/NP",
        "/sdcard/xinhao",
        "/sdcard/Download/advanced/",
        "/sdcard/.OShin",
    )

    private fun pkg(
        packageName: String,
        appName: String,
    ): Pair<String, String> = packageName to appName

    private fun MutableList<DangerousAppTarget>.addCategory(
        category: DangerousAppCategory,
        vararg apps: Pair<String, String>,
    ) {
        apps.forEach { (packageName, appName) ->
            add(
                DangerousAppTarget(
                    packageName = packageName,
                    appName = appName,
                    category = category,
                ),
            )
        }
    }
}

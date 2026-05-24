
  <img src="logo.png" alt="DuckDetector Logo" width="600px">

  <a href="https://developer.android.com"><img src="https://img.shields.io/badge/Android-minSdk%2029-3DDC84?logo=android&logoColor=white&style=flat-square" alt="Android"></a>
  <a href="https://developer.android.com"><img src="https://img.shields.io/badge/targetSdk-37-3DDC84?logo=android&logoColor=white&style=flat-square" alt="targetSdk"></a>
  <a href="https://kotlinlang.org"><img src="https://img.shields.io/badge/Kotlin-2.3.21-7F52FF?logo=kotlin&logoColor=white&style=flat-square" alt="Kotlin"></a>
  <a href="https://developer.android.com/jetpack/compose"><img src="https://img.shields.io/badge/Jetpack%20Compose-Material%203-4285F4?logo=jetpackcompose&logoColor=white&style=flat-square" alt="Jetpack Compose"></a>
  <img src="https://img.shields.io/badge/NDK-30.0.14904198-555555?style=flat-square" alt="NDK">
  <a href="https://github.com/eltavine/Duck-Detector-Refactoring/releases"><img src="https://img.shields.io/github/downloads/eltavine/Duck-Detector-Refactoring/total?style=flat-square" alt="Downloads"></a>
</p>

**DuckDetector** 是一个专注于**本地端、设备侧**证据收集的 Android 安全检测应用程序。它旨在识别 Root 相关的篡改、运行时 Hook、挂载操作（Mount）、密钥库可信度（Attestation Trust）以及虚拟化执行环境。
本应用结合了 **Jetpack Compose UI** 界面、**模块化 Kotlin 检测包** 以及 **底层 C++ / 汇编探针**，通过结构化的卡片形式展示详细的检测结果、方法覆盖范围及扫描状态摘要。

# ⚠️ **开发规范 / Development Rules**

在更改代码、工作流程或提交历史记录之前，请阅读 [CODING_STANDARDS.md](./CODING_STANDARDS.md)。
> changing code, workflows, or commit history.


# ✨ 项目亮点 / Highlights
- 🧩 **模块化检测架构 (Modular Architecture)**：具有特定功能的独立模块，各模块均包含其专属的 Repository、Mapper、ViewModel 和卡片 UI。
- ⚡ **原生启动预载 (Native Preload)**：通过透明的 `NativeActivity` 启动器实现底层及早预载，以捕捉极早期的挂载（Mount）和虚拟化痕迹。
- 🛡️ **底层 C++ 与汇编探针 (Native Probes)**：利用 C++ 和汇编实现的系统调用（Syscall）级别、时间敏感型、挂载和运行时可见性检查。
- 🔄 **跨进程与隔离进程验证 (Cross-Process Validation)**：通过多进程、隔离进程（Isolated Process）协同校验，降低对单一信号的依赖。
- 🔒 **纯本地离线优先 (Local & Privacy-First)**：默认情况下，TEE 吊销检查使用内置的静态快照。仅在用户手动于设置中开启“在线刷新”时才会访问网络。
---
# 🔍 检测覆盖范围 / Detector Coverage
目前应用已支持以下安全领域的启发式检测：
> `Bootloader` · `Custom ROM` · `Dangerous Apps` · `Kernel Check` · `LSPosed` · `Memory` · `Mount` · `Native Root` · `Play Integrity Fix` · `SELinux` · `SU` · `System Properties` · `TEE` · `Virtualization` · `Zygisk`
此外，项目内置 `dashboard`（仪表盘）、`settings`（设置）和 `deviceinfo`（设备信息）等辅助模块，提供数据聚合、用户控制和设备上下文展示。
---
# 📱 兼容性 / Compatibility

| 维度 / Target | 详情与说明 / Notes |
| :--- | :--- |
| **Android 版本** | 支持 Android 10+ (`minSdk 29`)，基于 `targetSdk 37` / `compileSdk 37.0` 构建。 |
| **架构支持 (ABI)** | 底层探针通过 NDK 层实现；部分低level的陷阱拦截（Trap paths）主要针对 `arm64-v8a` 架构进行了优化。 |
| **环境要求** | 无需 Root 权限即可运行，适用于纯净官方系统及各种定制/修改过的环境。 |
| **覆盖度表现** | 当 OEM 厂商或严格的沙盒规则限制访问时，部分检查可能会降级为 `support`、`unavailable` 或低覆盖度状态。 |
| **网络依赖** | 默认完全本地化。内置 TEE 吊销凭证离线运行，仅在手动刷新网络源时产生流量。 |

---
## 🎨 用户界面 / User Interface
- **Compose 仪表盘**：包含检测卡片、扫描状态摘要、高危发现（Top findings）以及详情展开行。
- **一致性卡片设计**：统一的共享卡片样式，确保长标签、检测状态和证据字符串在不同模块中均有极佳的可读性。
- **独立设置与信息流**：将高级控制、环境上下文与主检测逻辑分离，保证界面清爽。
---
## 📁 架构快照 / Architecture Snapshot
```text
Duck-Detector-Refactoring/
├─ app/
│  ├─ src/main/java/com/eltavine/duckdetector/
│  │  ├─ core/            # 核心公共组件与基础底座
│  │  ├─ features/        # 各检测特征模块
│  │  └─ ui/              # 全局通用 UI 与主题
│  └─ src/main/cpp/       # 底层 C++ / 汇编探针源码
├─ build-logic/           # Gradle 复合构建逻辑
├─ gradle/                # Gradle 包装器配置
├─ scripts/               # 自动化或辅助脚本
├─ build.gradle.kts
└─ settings.gradle.kts
```
绝大多数检测功能模块（Features）均遵循以下清晰的包结构：
 * domain：报告和结果的数据模型（Models）。
 * data：仓库（Repositories）、探针、原生桥接（Native Bridges）和系统服务助手。
 * presentation：数据映射器（Mappers）和 UI 状态状态机（UI-state reducers）。
 * ui：检测卡片组件和专属于该模块的 UI 模型。
> 💡 所有的原生探针都位于 app/src/main/cpp 下，最终编译成一个共享动态链接库（.so），用于预载捕获、挂载检查、虚拟化快照、渲染器校验以及低级别陷阱拦截。
> 
## 🛠️ 编译与构建 / Build
### 环境依赖 / Requirements
 * **Android Studio** (推荐最新稳定版)
 * Android SDK 37.0 & Android Build Tools 37.0.0
 * **JDK** 17
 * Android **NDK** 30.0.14904198
 * **CMake** 4.1.2
### 常用构建命令 / Build Commands
**编译 Debug 版本：**
```bash
# Windows 环境
gradlew.bat :app:assembleDebug
# Linux / macOS 环境
./gradlew :app:assembleDebug
```
**日常开发校验命令（推荐）：**
```bash
# 验证 Kotlin 编译、运行单元测试并打包
./gradlew :app:compileDebugKotlin :app:testDebugUnitTest :app:assembleDebug
```
> 🔐 **签名说明**：Release 版本的自动签名受到环境参数 ANDROID_KEYSTORE_PATH、ANDROID_KEYSTORE_PASSWORD、ANDROID_KEY_ALIAS 和 ANDROID_KEY_PASSWORD 的控制。当这四个环境变量完整存在时，构建系统将自动启用 ciRelease 签名配置。
> 
## 🔒 隐私与局限性 / Privacy & Limits
 * **本地化安全**：检测逻辑主要在设备本地运行，不收集或上传您的敏感隐私数据。
 * **非侵入式**：应用本身**不需要** Root 权限即可正常工作。
 * **启发式检测**：所有安全检测均基于启发式算法（Heuristics）。任何单一信号都不应孤立地作为绝对的可信凭证。
 * **硬件与厂商限制**：因 OEM 策略或沙盒规则，部分探针在特定机型上可能报告降级状态。部分低级底层检查依赖于 arm64-v8a ABI 架构。
## 📈 项目状态与趋势 / Status & Stars
本仓库正处于**积极演进和迭代**中。新的检测模块和启发式机制不断被加入，检测阈值也在持续微调，以尽可能降低在官方原厂系统上的误报率（False Positives）。
Star History Chart
## ⚖️ 免责声明 / Disclaimer
```text
本软件按“原样”提供，不提供任何明示或暗示的保证。本程序仅供教育、诊断和安全研究目的使用。
开发者对因使用本应用程序而导致的任何直接或间接损坏、数据丢失或系统不稳定不承担责任。
依赖启发式安全检测的风险由您自行承担。
This software is provided "as is", without warranty of any kind. It is designed
for educational, diagnostic, and security research purposes only. The developers
assume no liability for direct or indirect damage, data loss, or system
instability resulting from use of this application. Relying on heuristic
security detection is at your own risk.
```
## 📄 开源协议 / License
本项目基于 **Apache License 2.0** 协议开源。
## 👥 贡献者 / Contributors
感谢以下为 DuckDetector 做出贡献的开发者们！
<a href="https://github.com/eltavine/Duck-Detector-Refactoring/graphs/contributors">
<img src="https://contrib.rocks/image?repo=eltavine/Duck-Detector-Refactoring" />
</a>

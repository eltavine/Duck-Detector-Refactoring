<p align="center">
  <a href="https://github.com/eltavine/Duck-Detector-Refactoring/stargazers"><img src="https://img.shields.io/github/stars/eltavine/Duck-Detector-Refactoring?style=social" alt="GitHub Stars"></a>
  <a href="https://github.com/eltavine/Duck-Detector-Refactoring/network/members"><img src="https://img.shields.io/github/forks/eltavine/Duck-Detector-Refactoring?style=social" alt="GitHub Forks"></a>
  <a href="https://github.com/eltavine/Duck-Detector-Refactoring/releases"><img src="https://img.shields.io/github/v/release/eltavine/Duck-Detector-Refactoring?style=flat-square&logo=github" alt="最新版本"></a>
  <a href="https://github.com/eltavine/Duck-Detector-Refactoring/releases/tag/nightly"><img src="https://img.shields.io/badge/release-nightly-2F81F7?style=flat-square&logo=github" alt="Nightly 版本"></a>
  <a href="https://github.com/eltavine/Duck-Detector-Refactoring/releases"><img src="https://img.shields.io/github/downloads/eltavine/Duck-Detector-Refactoring/total?style=flat-square" alt="版本下载量"></a>
  <a href="https://t.me/duck_detector"><img src="https://img.shields.io/badge/Telegram-Channel-2CA5E0?logo=telegram&logoColor=white&style=flat-square" alt="Telegram 频道"></a>
  <a href="https://github.com/eltavine/Duck-Detector-Refactoring/blob/main/LICENSE"><img src="https://img.shields.io/github/license/eltavine/Duck-Detector-Refactoring?style=flat-square" alt="开源协议"></a>
</p>

<p align="center">
  <strong><a href="README.MD">English</a></strong> &nbsp; <strong><a href="README_ZH.MD">简体中文</a></strong>
</p>

<p align="center"><strong>基于 Kotlin 与原生探针的 Android 设备侧环境完整性诊断工具。</strong></p>

# 项目概述

DuckDetector 在 Android 设备上采集并关联与安全相关的证据，用于发现启动状态变化、Root 与 SU 痕迹、运行时注入或 Hook、挂载命名空间异常、系统属性篡改、可疑应用、KeyStore 与证明链异常，以及虚拟化迹象。

应用由 Jetpack Compose 界面、按功能组织的 Kotlin 代码和 C++/汇编原生库组成。检测结果是用于诊断的信号，不代表对设备“安全”或“已受损”的权威认证。

# 检测范围

当前覆盖以下功能域：

`Bootloader` · `Custom ROM` · `Dangerous Apps` · `Kernel Check` · `LSPosed` · `Memory` · `Mount` · `Native Root` · `Play Integrity Fix` · `SELinux` · `SU` · `System Properties` · `TEE` · `Virtualization` · `Zygisk`

其中，`Play Integrity Fix` 检测的是与完整性伪装修改相关的本地迹象，并不会返回 Google Play Integrity API 的官方判定。TEE 模块检查 Android KeyStore 与设备证明证据，包括证书链、安全级别、吊销数据，以及设备支持时的部分 KeyMint、StrongBox 和 Soter 行为。

项目还包含仪表盘、设备信息、设置、更新检查、通知、开源许可和通用 UI 等辅助功能包。

# 工作方式

- **按功能组织：** 每个检测域就近维护采集逻辑、领域模型、报告映射和界面代码。
- **启动早期采集：** 透明的 `NativeActivity` 在 `MainActivity` 之前运行，记录早期挂载与虚拟化证据。
- **原生探针：** 共享原生库负责直接系统调用、`/proc` 检查、计时测量、链接器与运行时可见性检查，以及特定架构的汇编路径。
- **进程隔离：** 部分 Zygisk、虚拟化、SELinux 和 TEE 检查运行在独立进程或隔离服务中，用于对照不同进程边界下的证据。
- **证据关联：** 仪表盘分别展示检测项与覆盖状态，不将单个启发式信号视为确定结论。

# 兼容性

| 项目 | 说明 |
| :--- | :--- |
| **Android** | 支持 Android 10 及以上版本（`minSdk 29`），使用 Android API 37 编译并作为目标版本。 |
| **ABI** | 为 `arm64-v8a`、`armeabi-v7a`、`x86` 和 `x86_64` 提供原生系统调用路径；部分计时与虚拟化陷阱探针仅适用于 `arm64-v8a`。 |
| **权限** | 应用无需 Root 权限，但 Android 权限、包可见性和平台沙盒仍会限制可观测范围。 |
| **设备差异** | OEM 修改、内核配置、Android 版本和沙盒策略可能导致探针显示不支持、不可用或低置信度。 |
| **网络使用** | 核心设备扫描在本地运行。TEE 吊销检查始终包含内置快照；下载 Google 最新吊销数据需要用户授权。应用还会在冷启动后以及用户从设置页操作时访问 GitHub 检查 Nightly 更新。 |

# 项目结构

```text
Duck-Detector-Refactoring/
├─ app/
│  ├─ src/main/java/com/eltavine/duckdetector/
│  │  ├─ core/            # 通用平台能力与 UI 基础设施
│  │  ├─ features/        # 检测功能与辅助功能包
│  │  └─ ui/              # 应用外壳、导航与主题
│  └─ src/main/cpp/       # C++、JNI 与各架构汇编代码
├─ build-logic/           # 约定插件与资源生成任务
├─ gradle/                # 版本目录与 Gradle Wrapper 文件
├─ scripts/               # 仓库维护脚本
├─ build.gradle.kts
└─ settings.gradle.kts
```

功能包会在适用时遵循以下边界：

- `data`：探针、解析器、Repository、JNI 桥接和 Android 服务访问
- `domain`：报告、结果模型和状态定义
- `presentation`：ViewModel、报告到 UI 的映射和界面状态
- `ui`：Compose 卡片、页面和功能专用展示模型

原生源码最终编译为共享库 `libduckdetector.so`，Kotlin 代码通过各功能域的 JNI 桥接读取原生结果。

# 构建

## 环境要求

- Android Studio，并安装 Android SDK Platform 37 与 Build Tools 37.0.0
- JDK 17
- Android NDK 30.0.16138531
- CMake 4.1.2

依赖与工具版本以 [`gradle.properties`](./gradle.properties) 和 [`gradle/libs.versions.toml`](./gradle/libs.versions.toml) 为准。

## 常用命令

```bash
# macOS / Linux
./gradlew :app:assembleDebug

# Windows
gradlew.bat :app:assembleDebug
```

本地完整校验可执行：

```bash
./gradlew :app:compileDebugKotlin :app:testDebugUnitTest :app:assembleDebug
```

参与开发前请阅读 [`CODING_STANDARDS.md`](./CODING_STANDARDS.md)。

## Release 签名

只有同时设置以下四个环境变量时，构建才会使用 `ciRelease` 签名配置：

- `ANDROID_KEYSTORE_PATH`
- `ANDROID_KEYSTORE_PASSWORD`
- `ANDROID_KEY_ALIAS`
- `ANDROID_KEY_PASSWORD`

未完整配置时，本地 `release` 构建会使用 debug 密钥签名，不能将该产物视为官方发布版本。

# 隐私与限制

- 检测在设备端执行，但项目不声称能够发现所有经过修改的运行环境。
- 具备联网能力的功能包括：经用户授权的 TEE 吊销数据刷新、GitHub 更新元数据与变更记录检查，以及用户主动打开的外部链接。
- 启发式结果可能出现误报、漏报、不支持的检查或证据不完整。
- 硬件 KeyStore、StrongBox、Binder 行为、`/proc`、SELinux、挂载命名空间等底层接口会因设备和系统版本而异。

# 项目趋势

<a href="https://www.star-history.com/?repos=eltavine%2FDuck-Detector-Refactoring&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=eltavine/Duck-Detector-Refactoring&type=date&theme=dark&legend=top-left&sealed_token=z8Kbufd8a78_gJi-_n_U1dbqg3bT3wexECwhrq7Vx1QpfiXBUdPXV5w_rUQSnu86aVeWxIJJENg8tVTng5ul8xki40oK_UhKF3-_gZgvrhWzbtd7OKm9kg" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=eltavine/Duck-Detector-Refactoring&type=date&legend=top-left&sealed_token=z8Kbufd8a78_gJi-_n_U1dbqg3bT3wexECwhrq7Vx1QpfiXBUdPXV5w_rUQSnu86aVeWxIJJENg8tVTng5ul8xki40oK_UhKF3-_gZgvrhWzbtd7OKm9kg" />
   <img alt="Star 历史趋势图" src="https://api.star-history.com/chart?repos=eltavine/Duck-Detector-Refactoring&type=date&legend=top-left&sealed_token=z8Kbufd8a78_gJi-_n_U1dbqg3bT3wexECwhrq7Vx1QpfiXBUdPXV5w_rUQSnu86aVeWxIJJENg8tVTng5ul8xki40oK_UhKF3-_gZgvrhWzbtd7OKm9kg" />
 </picture>
</a>

# 免责声明

本软件按“原样”提供，不附带任何形式的保证，仅用于教育、诊断和安全研究。开发者不对使用本软件造成的损坏、数据丢失或系统不稳定承担责任。解释启发式结果时，应同时考虑设备、系统版本和实际可用的探针覆盖范围。

# 开源协议

DuckDetector 基于 [Apache License 2.0](./LICENSE) 开源。

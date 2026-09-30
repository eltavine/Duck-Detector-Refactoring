<p align="center">
  <img src="app/src/main/ic_launcher-playstore.png" alt="DuckDetector 标志" width="128">
</p>

<h1 align="center">DuckDetector</h1>

<p align="center"><strong>基于 Kotlin 与原生探针的 Android 设备侧环境完整性诊断工具。</strong></p>

<p align="center">
  <strong>
    <a href="https://github.com/eltavine/Duck-Detector-Refactoring/releases/tag/nightly">下载 Nightly</a> ·
    <a href="#快速上手">文档</a> ·
    <a href="docs/guides/sdk-integration.md">SDK 集成</a>
  </strong>
</p>

<p align="center">
  <a href="https://github.com/eltavine/Duck-Detector-Refactoring/actions/workflows/build.yml"><img src="https://img.shields.io/github/actions/workflow/status/eltavine/Duck-Detector-Refactoring/build.yml?branch=main&amp;style=flat-square&amp;label=build&amp;logo=githubactions&amp;logoColor=white" alt="主分支构建工作流状态"></a>
  <a href="#兼容性"><img src="https://img.shields.io/badge/Android-10%2B-3DDC84?style=flat-square&amp;logo=android&amp;logoColor=white" alt="支持 Android 10 及以上版本"></a>
  <a href="https://github.com/eltavine/Duck-Detector-Refactoring/blob/main/LICENSE"><img src="https://img.shields.io/github/license/eltavine/Duck-Detector-Refactoring?style=flat-square" alt="开源协议"></a>
  <a href="https://t.me/duck_detector"><img src="https://img.shields.io/badge/Telegram-Channel-2CA5E0?logo=telegram&logoColor=white&style=flat-square" alt="Telegram 频道"></a>
</p>

<p align="center">
  <a href="https://trendshift.io/repositories/44818?utm_source=repository-badge&amp;utm_medium=badge&amp;utm_campaign=badge-repository-44818" target="_blank" rel="noopener noreferrer"><img src="https://trendshift.io/api/badge/repositories/44818" alt="eltavine/Duck-Detector-Refactoring | Trendshift" width="250" height="55"></a>
  <a href="https://trendshift.io/repositories/44818?utm_source=trendshift-badge&amp;utm_medium=badge&amp;utm_campaign=badge-trendshift-44818" target="_blank" rel="noopener noreferrer"><img src="https://trendshift.io/api/badge/trendshift/repositories/44818/daily?language=Kotlin" alt="eltavine/Duck-Detector-Refactoring | Trendshift Kotlin 每日排名" width="250" height="55"></a>
</p>

<p align="center">
  <a href="README.md">English</a> &nbsp; <a href="README_ZH.md">简体中文</a>
</p>

# 项目概述

DuckDetector 在 Android 设备上采集并关联与安全相关的证据，用于发现启动状态变化、Root 与 SU 痕迹、运行时注入或 Hook、挂载命名空间异常、系统属性篡改、可疑应用、KeyStore 与证明链异常，以及虚拟化迹象。

应用由 Jetpack Compose 界面、按功能拆分的 Gradle 模块和 C++/汇编原生库组成；同一套检测器也以不含 UI 的 SDK AAR 形式发布，可以嵌入其他应用。检测结果是用于诊断的信号，不代表对设备“安全”或“已受损”的权威认证。

# 快速上手

1. **下载：** 从 [Nightly 版本](https://github.com/eltavine/Duck-Detector-Refactoring/releases/tag/nightly)下载 APK。Nightly 构建从 `main` 分支发布，并同步推送到 [Telegram 频道](https://t.me/duck_detector)；目前尚无正式版本。
2. **安装：** 安装到 Android 10 及以上版本的设备，无需 Root 权限。
3. **扫描：** 首次启动时需要同意用户协议，并完成几项启动选项：通知、Live Update、TEE 检查所用的在线吊销数据刷新，以及包可见性。之后扫描会自动开始，每个检测器完成后，对应卡片随即显示结果。
4. **解读结果：** 参照下文说明。报告结果或寻求帮助时，请[提交 Issue](https://github.com/eltavine/Duck-Detector-Refactoring/issues)，并附上用仪表盘顶部 **Export Report** 保存的报告文件；只有摘要截图是不够的。

## 如何解读结果

每张卡片显示以下状态之一：

| 状态 | 含义 |
| :--- | :--- |
| **Danger**、**Warning** | 检测器观察到了证据，卡片会列出具体发现。 |
| **All Clear** | 探针已运行，未发现其检查的任何证据；这并不能证明设备未被修改。 |
| **Info**（Support） | 探针在此设备上不受支持或不可用，此时没有发现不代表不存在。 |
| **Info**（Error） | 检查执行失败，卡片会说明原因。 |

想了解某个检测器检查什么、为什么构成证据，可从[检测范围](#检测范围)打开它的证据记录。

# 检测范围

当前覆盖以下功能域，每项都链接到对应的证据记录（英文），说明检测器检查什么、为什么构成证据，以及哪些情况它观察不到：

[`Bootloader`](./feature/bootloader/EVIDENCE.md) · [`Custom ROM`](./feature/customrom/EVIDENCE.md) · [`Dangerous Apps`](./feature/dangerousapps/EVIDENCE.md) · [`Kernel Check`](./feature/kernelcheck/EVIDENCE.md) · [`LSPosed`](./feature/lsposed/EVIDENCE.md) · [`Memory`](./feature/memory/EVIDENCE.md) · [`Mount`](./feature/mount/EVIDENCE.md) · [`Native Root`](./feature/nativeroot/EVIDENCE.md) · [`Play Integrity Fix`](./feature/playintegrityfix/EVIDENCE.md) · [`SELinux`](./feature/selinux/EVIDENCE.md) · [`SU`](./feature/su/EVIDENCE.md) · [`System Properties`](./feature/systemproperties/EVIDENCE.md) · [`TEE`](./feature/tee/EVIDENCE.md) · [`Virtualization`](./feature/virtualization/EVIDENCE.md) · [`Zygisk`](./feature/zygisk/EVIDENCE.md)

其中，`Play Integrity Fix` 检测的是与完整性伪装修改相关的本地迹象，并不会返回 Google Play Integrity API 的官方判定。TEE 模块检查 Android KeyStore 与设备证明证据，包括证书链、安全级别、吊销数据，以及设备支持时的部分 KeyMint、StrongBox 和 Soter 行为。

项目还包含仪表盘、设备信息、设置、更新检查、通知、开源许可和通用 UI 等辅助模块。

# 工作方式

- **按功能拆分模块：** 每个检测器在自己的 Gradle 模块中维护采集、判定规则、报告投影与界面，多个检测器共用的采集代码放在 capability 模块中。
- **启动早期采集：** 透明的 `NativeActivity` 在 `MainActivity` 之前运行，记录早期挂载与虚拟化证据。
- **原生探针：** 共享原生库负责直接系统调用、`/proc` 检查、计时测量、链接器与运行时可见性检查，以及特定架构的汇编路径。
- **进程隔离：** 部分 Zygisk、Mount、Native Root、虚拟化、SELinux、LSPosed 和 TEE 检查运行在独立进程或隔离服务中，用于对照不同进程边界下的证据。
- **证据关联：** 仪表盘分别展示检测项与覆盖状态，不将单个启发式信号视为确定结论。

# 兼容性

| 项目 | 说明 |
| :--- | :--- |
| **Android** | 支持 Android 10 及以上版本（`minSdk 29`），使用 Android API 37 编译并作为目标版本。 |
| **ABI** | 为 `arm64-v8a`、`armeabi-v7a`、`x86` 和 `x86_64` 提供原生系统调用路径；部分计时与虚拟化陷阱探针仅适用于 `arm64-v8a`。 |
| **权限** | 应用无需 Root 权限，但 Android 权限、包可见性和平台沙盒仍会限制可观测范围。 |
| **设备差异** | OEM 修改、内核配置、Android 版本和沙盒策略可能导致探针显示不支持、不可用或低置信度。 |
| **网络使用** | 核心设备扫描在本地运行。TEE 吊销检查始终包含内置快照；下载 Google 最新吊销数据需要用户授权。应用还会在冷启动后以及用户从设置页操作时访问 GitHub 检查 Nightly 更新。开启 GitHub 加速后（中文用户会收到开启询问，也可在设置中切换），这些检查和 Nightly 下载改由第三方服务 [gh-proxy.com](https://gh-proxy.com/docs) 中转。 |

# 项目结构

```text
Duck-Detector-Refactoring/
├─ app/                   # UI 组合根：Activity、仪表盘卡片、通知
├─ sdk/runtime/           # Headless 组合根：检测器目录、扫描 API、进程钩子、原生库注册表
├─ sdk/aar/               # 可分发的 SDK：把所有 headless 模块融合成一个 AAR
├─ core/                  # 契约与共享基础设施：证据、原生载荷、平台访问、报告、扫描生命周期、检测器、UI
├─ capability/            # 多个检测器共享的证据采集
├─ feature/               # 每个目录一个检测器或辅助功能，按层拆分
├─ samples/sdk-consumer/  # 只依赖已发布 AAR 构建的独立示例应用
├─ build-logic/           # 约定插件、模块边界与依赖校验、生成资源任务
├─ uihelper/              # 锁定提交的 Git 子模块：MIUIX / Material UI，独立 Gradle 构建
├─ docs/                  # 架构概览、指南与后续事项
├─ .github/policies/      # 模块、原生、检测器接触点、反射与文本协议策略
├─ .github/scripts/       # 仓库守卫脚本及其自测
├─ gradle/                # 版本目录与 Gradle Wrapper 文件
├─ scripts/               # 检测器脚手架与仓库维护脚本
├─ build.gradle.kts
└─ settings.gradle.kts
```

每个检测器是 `feature/<name>/` 下的一组 Gradle 模块：

- `domain`：结果模型、报告模型、状态定义与判定规则（纯 JVM）
- `data`：探针、解析器、Repository、JNI 桥接和 Android 服务访问
- `presentation`：卡片模型、从领域报告到卡片的映射与报告投影（纯 JVM）
- `detector`：唯一的 headless `<Name>Detector` 对象，把其余各层绑定给 SDK 与应用
- `ui`：Compose 卡片、检测器 consent 的提示，以及检测器接入仪表盘的入口

依赖方向为 `:app` 指向 SDK，二者指向 feature，feature 指向 capability，capability 指向 core；feature 之间互不依赖，每个模块只声明自己实际使用的依赖。构建与 CI 会校验这些规则，详见[架构概览](./docs/architecture/README.md)。

原生源码按单元组织：每个单元位于其所属模块的 `src/main/cpp/<unit>/`，编译为独立的 object library 并链接进 `libduckdetector.so`；Kotlin 代码通过同一模块中的 JNI 桥接读取原生结果。

新增检测器只改动它自己的目录，以及 `DetectorCatalog` 中的一行；带 native unit 时再加一行注册和一条策略。应用会根据各 ui 模块自动生成仪表盘卡片列表。一条命令即可生成全部代码；生成结果可以直接构建，在探针写好之前显示“Not evaluated”：

```bash
python3 scripts/new_detector.py <name> --description "检测什么，以及为什么它构成证据"
```

后续步骤见 [Adding a detector](./docs/guides/adding-a-detector.md)。要在其他应用中运行这些检测器，见 [Using the SDK](./docs/guides/sdk-integration.md)。

# 构建

## 环境要求

- Android Studio，并安装 Android SDK Platform 37 与 Build Tools 37.0.0
- JDK 17
- Android NDK 30.0.16138531
- CMake 4.1.2

依赖与工具版本以 [`gradle.properties`](./gradle.properties) 和 [`gradle/libs.versions.toml`](./gradle/libs.versions.toml) 为准。

克隆后需要初始化 UI 子模块（也可在克隆时使用 `--recurse-submodules`）。它作为独立 Gradle 构建接入，不进入无 UI 的检测 SDK：

```bash
git submodule update --init --recursive
```

## 常用命令

```bash
# macOS / Linux
./gradlew :app:assembleDebug

# Windows
gradlew.bat :app:assembleDebug
```

本地完整校验可执行：

```bash
./gradlew unitTest :app:assembleDebug :app:lintDebug buildHealth
for s in .github/scripts/check-*.py; do python3 "$s"; done
```

同一次构建还会产出不含任何 UI 的 headless SDK，打包为一个 AAR 并发布到 `sdk/aar/build/repository`（见 [Using the SDK](./docs/guides/sdk-integration.md)）：

```bash
./gradlew :sdk:aar:publish
```

[Nightly Release](https://github.com/eltavine/Duck-Detector-Refactoring/releases/tag/nightly) 会同时提供 APK 和 SDK AAR。

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
- 具备联网能力的功能包括：经用户授权的 TEE 吊销数据刷新、GitHub 更新元数据与变更记录检查（开启 GitHub 加速后经由 gh-proxy.com），以及用户主动打开的外部链接。
- 启发式结果可能出现误报、漏报、不支持的检查或证据不完整。
- 硬件 KeyStore、StrongBox、Binder 行为、`/proc`、SELinux、挂载命名空间等底层接口会因设备和系统版本而异。

# 项目趋势

<p align="center">
  <a href="https://www.star-history.com/?repos=eltavine%2FDuck-Detector-Refactoring&type=date&legend=top-left">
   <picture>
     <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=eltavine/Duck-Detector-Refactoring&type=date&theme=dark&legend=top-left&sealed_token=z8Kbufd8a78_gJi-_n_U1dbqg3bT3wexECwhrq7Vx1QpfiXBUdPXV5w_rUQSnu86aVeWxIJJENg8tVTng5ul8xki40oK_UhKF3-_gZgvrhWzbtd7OKm9kg" />
     <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=eltavine/Duck-Detector-Refactoring&type=date&legend=top-left&sealed_token=z8Kbufd8a78_gJi-_n_U1dbqg3bT3wexECwhrq7Vx1QpfiXBUdPXV5w_rUQSnu86aVeWxIJJENg8tVTng5ul8xki40oK_UhKF3-_gZgvrhWzbtd7OKm9kg" />
     <img alt="Star 历史趋势图" src="https://api.star-history.com/chart?repos=eltavine/Duck-Detector-Refactoring&type=date&legend=top-left&sealed_token=z8Kbufd8a78_gJi-_n_U1dbqg3bT3wexECwhrq7Vx1QpfiXBUdPXV5w_rUQSnu86aVeWxIJJENg8tVTng5ul8xki40oK_UhKF3-_gZgvrhWzbtd7OKm9kg" />
   </picture>
  </a>
</p>

# 免责声明

本软件按“原样”提供，不附带任何形式的保证，仅用于教育、诊断和安全研究。开发者不对使用本软件造成的损坏、数据丢失或系统不稳定承担责任。解释启发式结果时，应同时考虑设备、系统版本和实际可用的探针覆盖范围。

# 开源协议

DuckDetector 基于 [Apache License 2.0](./LICENSE) 开源。

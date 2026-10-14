# Nightly 更新的下载与安装边界

更新发现和变更列表可使用用户选择的 GitHub 代理。下载前，下载器必须通过官方
`https://github.com/eltavine/Duck-Detector-Refactoring/releases/download/nightly/update.json`
独立获取清单，并核对 APK 的名称、官方 URL、大小及 SHA-256。该请求不使用代理路由。
官方请求失败、清单格式无效或元数据不一致时，下载失败；不会仅凭代理提供的摘要继续。
这仍依赖系统 TLS 信任、GitHub 及发布账户的安全，不提供对发布账户失陷的保证。
官方地址无法直连时，应用内下载也无法完成，即使代理本身可达。

清单解析器和下载器均拒绝超过 256 MiB 的 APK。已知 Content-Length 必须等于清单大小；
未知长度的响应仍逐块在写入前检查清单大小。摘要在复制时计算，精确大小与摘要均通过后
才将临时文件重命名为以摘要命名的 APK。失败和取消均清理临时文件。网络请求最多接受
五次重定向，每一跳都要求 HTTPS，拒绝 URL 凭据。连接和读取分别设有超时；取消在连接跳转
和读取循环间检查，正在进行的阻塞网络读取仍受读取超时限制。

进度的分母始终为清单大小，中间回调间隔至少 250 ms；成功验证并重命名后报告最终进度。
下载请求、进度和就绪路径绑定完整清单快照。更新清单改变时取消旧请求，并通过请求代次
丢弃迟到回调；StateFlow 原子更新保留并发发生的对话框关闭操作。

安装使用应用私有缓存子目录的 FileProvider，只授予临时读取权限。Android 8 / API 26
及以上先检查未知来源安装授权；返回设置后仍保留下载文件。缓存文件丢失、不可读或大小发生变化时
切换到可重试下载状态。打开系统安装器只表示安装界面已启动，不表示安装已完成。

## 技术依据

- [GitHub release assets](https://docs.github.com/en/rest/releases/assets)：资产下载可重定向到存储地址。
- [HttpURLConnection](https://developer.android.com/reference/java/net/HttpURLConnection)：连接、响应头与读取超时契约。
- [FileProvider](https://developer.android.com/reference/androidx/core/content/FileProvider)：内容 URI、路径范围与临时读取授权。
- [PackageManager.canRequestPackageInstalls](https://developer.android.com/reference/android/content/pm/PackageManager#canRequestPackageInstalls())：API 26 起的来源授权检查。
- [Android 16 ApplicationPackageManager](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-16.0.0_r1/core/java/android/app/ApplicationPackageManager.java)：该检查调用系统 PackageManager 服务，服务错误可能传播为运行时异常；安装适配层将失败显式返回。

## 可复现验证

```sh
./gradlew :feature:update:data:testDebugUnitTest :feature:update:ui:testDebugUnitTest :feature:update:presentation:test :app:testDebugUnitTest
./gradlew :feature:update:data:lintDebug :feature:update:ui:lintDebug :app:lintDebug :app:assembleDebug
```

下载测试使用本地 HTTP 服务模拟响应，注入连接适配函数；生产入口仍要求 HTTPS。
测试覆盖摘要与长度不匹配、官方元数据不一致或不可用、固定大小上限、分块响应超量、
HTTPS 重定向与降级拒绝、进度节流、取消清理及重命名失败。
状态测试覆盖缓存失效后的重试、授权设置后保留下载、迟到回调、乱序清单检查、
关闭对话框、重复点击及下载异常恢复。系统设置与安装器交互仍需要设备验证。

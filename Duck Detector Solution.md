**System Properties**
Security and runtime
-关闭开发者模式和usb调试
Verified boot
-使用resetprop弱隐藏

**Custom ROM**
-检测到第三方rom信息可通过susfs隐藏

**LSPosed**
检测到LSPosed模块或LSPosed模块
-更新lsp
-使用应用隐藏列表隐藏lsp模块

**Bootloader**
检测到解锁bootloader
-通过resetprop弱隐藏
-通过可信执行环境检测(tee)

检测到Widevine L1凭据一致性异常
-精确sentinel属性、明确支持HW_SECURE_ALL却返回较低最大会话级别，或Java/native属性不一致作为DRM一致性信号
-Android允许不支持请求等级时选择下一较低等级，VirtualDevice也可调整最大等级；能力预检未确认HW_SECURE_ALL时不将较低会话判为异常
-Provisioning、显式安全级别会话请求或本地key request失败仅表示检测不完整，不等于凭据无效
-Widevine Warning/Danger会影响Bootloader Card的一致性assessment和严重度，但不改写权威BootloaderState；UI以问号标记该分离状态

**TEE**
可信执行环境检测与预期不符
-使用Oh My Keymint模块或近期更新的keystone伪装模块
-更换keybox

**Zygisk**
检测到Zygisk实现
-更新Zygisk实现如zygisknext rezygisk
-检测Zygisk模块建议通过关闭模块进行排除

**SU**
检测到su命令
-检测root权限是否排除检测软件

**SELinux**
SELinux状态异常或zygote泄露
-SELinux设为严格模式
-更新kernelsu包括内核并且在设置中开启隐藏SELinux修改

**Mount**
检测到挂载
-更新元模块
-更换元模块实现

**Play Integrity Fix**
检侧到Play Integrity信息与预期不服
-移除与Play Integrity相关模块
-更新Play Integrity相关模块
-更新设备系统

**Kernel Check**
检测到内核信息与预期不符或CVE-2024-43093未修复
-使用官方内核
-更新设备系统或者使用修复补丁

**Dangerous Apps**
检测到隐藏应用或被标记应用
-使用应用隐藏列表
-MT2需在MT管理器设置中更改MT2位置并删除原MT2推荐修改到
/storage/emulated/0/Download
-如果使用应用隐藏隐藏列表还是被检测可能是因为CEV漏洞使用FuseFixer等修复工具或更新系统到2026-02补丁


# System properties capability evidence record

Status: reviewed

The system properties capability reads Android property-service values through several access paths and snapshots native property areas. A separate process-local JVM reader is shared by System Properties and Network Risk; its namespace is not the Android property service.

## Signals

### Multi-source property reads

- Observable signal: one property's value through android.os.SystemProperties, getprop, System.getProperty and __system_property_get.
- Producing subsystem: Bionic shared property areas written by init for reflection/getprop/libc; a separate process-local java.util.Properties object for System.getProperty.
- Mechanism: Android reflection/getprop/libc paths converge on the property service. JVM values are supplemental and may be absent or independently modified; equality with Android property-service values is not a platform guarantee.
- References: AOSP [frameworks/base SystemProperties](https://android.googlesource.com/platform/frameworks/base/+/android-15.0.0_r1/core/java/android/os/SystemProperties.java), [libcore System.getProperty](https://android.googlesource.com/platform/libcore/+/android-15.0.0_r1/ojluni/src/main/java/java/lang/System.java); bionic libc/include/sys/system_properties.h; system/core init/property_service.cpp; [Android System API](https://developer.android.com/reference/java/lang/System#getProperty(java.lang.String)).
- Applicability: JVM System.getProperty is public API 1; the namespace separation and Android property wrapper were reviewed at android-15.0.0_r1. Hidden/native Android access remains release-sensitive.
- Visibility limits: SELinux restricts Android property-service reads. JVM reads have separate process scope; the shared readJvmProperty helper preserves success-null versus failure and does not cache. The older multi-source consumer retains its existing empty fallback.
- Result states: consistent, mismatch, unreadable.
- Interpretation: Consumers apply scoped rules; JVM disagreement alone cannot establish an Android property hook. The Network Risk consumer compares only the AOSP-synchronized HTTP proxy endpoint and treats differences as inconclusive INFO.

### Raw boot parameters and property areas

- Observable signal: androidboot.* values in /proc/cmdline and /proc/bootconfig, read-only property handles, and holes in /dev/__properties__.
- Producing subsystem: the bootloader's command line and bionic's property areas.
- Mechanism: init imports androidboot.* as ro.boot.*, so the raw and runtime values agree unless something rewrote one of them.
- References: system/core init/property_service.cpp (ProcessKernelCmdline and ProcessBootconfig); bionic libc/include/sys/system_properties.h. Discovery only for the property area hole heuristics.
- Applicability: bootconfig on Android 12 and later kernels.
- Visibility limits: /proc/cmdline and bootconfig are often unreadable for apps.
- Result states: read, unreadable.
- Interpretation: consumers compare the raw values with the runtime ones.

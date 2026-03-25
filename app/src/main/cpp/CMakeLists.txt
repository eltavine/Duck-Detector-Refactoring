cmake_minimum_required(VERSION 4.1.2)
project("duckdetector" LANGUAGES C CXX ASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(TEE_COMMON_SOURCES
    tee/common/jni_bridge.cpp
    tee/common/result_codec.cpp
    tee/common/syscall_facade.cpp
    tee/common/timing_stats.cpp
)

set(TEE_KEYSTORE_SOURCES
    tee/keystore/environment_probe.cpp
)

set(TEE_TRICKYSTORE_SOURCES
    tee/trickystore/trickystore_probe.cpp
)

set(TEE_DER_SOURCES
    tee/der/der_probe.cpp
)

set(DANGEROUS_APPS_SOURCES
    dangerousapps/native_bridge.cpp
)

set(SU_SOURCES
    su/native_bridge.cpp
)

set(SELINUX_SOURCES
    selinux/audit_probe.cpp
    selinux/native_bridge.cpp
)

set(CUSTOM_ROM_SOURCES
    customrom/native_bridge.cpp
)

set(KERNEL_CHECK_SOURCES
    kernelcheck/native_bridge.cpp
)

set(SYSTEM_PROPERTIES_SOURCES
    systemproperties/property_utils.cpp
    systemproperties/boot_param_utils.cpp
    systemproperties/prop_area_probe.cpp
    systemproperties/readonly_serial_probe.cpp
    systemproperties/native_bridge.cpp
)

set(MOUNT_SOURCES
    mount/detector_core.cpp
    mount/native_bridge.cpp
)

set(PRELOAD_SOURCES
    preload/early_detector.cpp
    preload/virtualization_early_detector.cpp
    preload/preload_entry.cpp
)

set(MEMORY_SOURCES
    memory/common/codec.cpp
    memory/common/maps_reader.cpp
    memory/detectors/function_hook_detector.cpp
    memory/detectors/maps_anomaly_detector.cpp
    memory/detectors/fd_detector.cpp
    memory/detectors/signal_detector.cpp
    memory/detectors/vdso_detector.cpp
    memory/detectors/linker_detector.cpp
    memory/snapshot_builder.cpp
    memory/native_bridge.cpp
)

set(PLAY_INTEGRITY_FIX_SOURCES
    playintegrityfix/common/codec.cpp
    playintegrityfix/probes/property_probe.cpp
    playintegrityfix/probes/maps_probe.cpp
    playintegrityfix/snapshot_builder.cpp
    playintegrityfix/native_bridge.cpp
)

set(NATIVE_ROOT_SOURCES
    nativeroot/common/codec.cpp
    nativeroot/common/io_utils.cpp
    nativeroot/cgroup_bridge.cpp
    nativeroot/probes/prctl_probe.cpp
    nativeroot/probes/ksu_supercall_probe.cpp
    nativeroot/probes/susfs_probe.cpp
    nativeroot/probes/self_process_ioc_probe.cpp
    nativeroot/probes/cgroup_process_probe.cpp
    nativeroot/probes/path_probe.cpp
    nativeroot/probes/process_probe.cpp
    nativeroot/probes/kernel_probe.cpp
    nativeroot/probes/property_probe.cpp
    nativeroot/snapshot_builder.cpp
    nativeroot/native_bridge.cpp
)

set(LSPOSED_SOURCES
    lsposed/common/codec.cpp
    lsposed/probes/maps_probe.cpp
    lsposed/probes/heap_probe.cpp
    lsposed/snapshot_builder.cpp
    lsposed/native_bridge.cpp
)

set(ZYGISK_SOURCES
    zygisk/common/codec.cpp
    zygisk/probes/fd_trap.cpp
    zygisk/probes/solist_probe.cpp
    zygisk/probes/vmap_probe.cpp
    zygisk/probes/atexit_probe.cpp
    zygisk/probes/smaps_probe.cpp
    zygisk/probes/namespace_probe.cpp
    zygisk/probes/linker_hook_probe.cpp
    zygisk/probes/stack_leak_probe.cpp
    zygisk/probes/seccomp_probe.cpp
    zygisk/probes/heap_entropy_probe.cpp
    zygisk/probes/thread_probe.cpp
    zygisk/probes/fd_probe.cpp
    zygisk/snapshot_builder.cpp
    zygisk/native_bridge.cpp
    zygisk/fdtrap_bridge.cpp
)

set(VIRTUALIZATION_SOURCES
    virtualization/egl_probe.cpp
    virtualization/snapshot_builder.cpp
    virtualization/honeypot_traps.cpp
    virtualization/native_bridge.cpp
)

set(TEE_ASM_SOURCES)
set(VIRTUALIZATION_ASM_SOURCES)
if(ANDROID_ABI STREQUAL "arm64-v8a")
    list(APPEND TEE_ASM_SOURCES asm/arm64/syscall_fastpath.S)
    list(APPEND TEE_ASM_SOURCES asm/arm64/tee_timer_arm64.S)
    list(APPEND VIRTUALIZATION_ASM_SOURCES asm/arm64/virtualization_traps.S)
elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
    list(APPEND TEE_ASM_SOURCES asm/arm/syscall_fastpath.S)
elseif(ANDROID_ABI STREQUAL "x86")
    list(APPEND TEE_ASM_SOURCES asm/x86/syscall_fastpath.S)
elseif(ANDROID_ABI STREQUAL "x86_64")
    list(APPEND TEE_ASM_SOURCES asm/x86_64/syscall_fastpath.S)
endif()

add_library(duckdetector SHARED
    ${TEE_COMMON_SOURCES}
    ${TEE_KEYSTORE_SOURCES}
    ${TEE_TRICKYSTORE_SOURCES}
    ${TEE_DER_SOURCES}
    ${DANGEROUS_APPS_SOURCES}
    ${SU_SOURCES}
    ${SELINUX_SOURCES}
    ${CUSTOM_ROM_SOURCES}
    ${KERNEL_CHECK_SOURCES}
    ${SYSTEM_PROPERTIES_SOURCES}
    ${MOUNT_SOURCES}
    ${PRELOAD_SOURCES}
    ${MEMORY_SOURCES}
    ${PLAY_INTEGRITY_FIX_SOURCES}
    ${NATIVE_ROOT_SOURCES}
    ${LSPOSED_SOURCES}
    ${ZYGISK_SOURCES}
    ${VIRTUALIZATION_SOURCES}
    ${TEE_ASM_SOURCES}
    ${VIRTUALIZATION_ASM_SOURCES}
)

include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_supported)
if(ipo_supported)
    set_property(TARGET duckdetector PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
endif()

target_compile_options(duckdetector PRIVATE
    $<$<AND:$<CONFIG:Release>,$<COMPILE_LANGUAGE:C>>:-O2 -ffunction-sections -fdata-sections -fvisibility=hidden>
    $<$<AND:$<CONFIG:Release>,$<COMPILE_LANGUAGE:CXX>>:-O2 -ffunction-sections -fdata-sections -fvisibility=hidden -fvisibility-inlines-hidden>
)

target_link_options(duckdetector PRIVATE
    $<$<CONFIG:Release>:-Wl,--gc-sections>
)

target_include_directories(duckdetector PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(duckdetector
    android
    EGL
    GLESv2
    log
)

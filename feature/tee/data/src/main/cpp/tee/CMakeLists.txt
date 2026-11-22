duckdetector_native_unit(duckdetector_tee
    common/jni_bridge.cpp
    common/result_codec.cpp
    common/local_timer_setup.cpp
    common/syscall_facade.cpp
    common/timing_stats.cpp
    keystore/environment_probe.cpp
    trickystore/trickystore_honeypot.cpp
    trickystore/trickystore_honeypot_analysis.cpp
    trickystore/trickystore_backend_mismatch.cpp
    trickystore/trickystore_hooks.cpp
    trickystore/trickystore_io.cpp
    trickystore/trickystore_maps.cpp
    trickystore/trickystore_probe.cpp
    der/der_probe.cpp
)

if(ANDROID_ABI STREQUAL "arm64-v8a")
    target_sources(duckdetector_tee PRIVATE
        asm/arm64/syscall_fastpath.S
    )
elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
    target_sources(duckdetector_tee PRIVATE
        asm/arm/syscall_fastpath.S
    )
elseif(ANDROID_ABI STREQUAL "x86")
    target_sources(duckdetector_tee PRIVATE
        asm/x86/syscall_fastpath.S
    )
elseif(ANDROID_ABI STREQUAL "x86_64")
    target_sources(duckdetector_tee PRIVATE
        asm/x86_64/syscall_fastpath.S
    )
endif()

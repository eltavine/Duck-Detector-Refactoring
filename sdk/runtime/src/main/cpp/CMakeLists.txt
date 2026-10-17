cmake_minimum_required(VERSION 4.1.2)
project("duckdetector" LANGUAGES C CXX ASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_supported)

# Every native unit, in link order, with the module that owns it. A unit lives in its owner's
# src/main/cpp/<unit> directory with a CMakeLists.txt that lists its sources, and
# .github/policies/native-boundaries.json states which other units it may include.
set(DUCKDETECTOR_NATIVE_UNITS
    common           core/native
    tee              feature/tee/data
    packageinventory capability/packageinventory/data
    dangerousapps    feature/dangerousapps/data
    su               feature/su/data
    selinuxpolicy    capability/selinuxpolicy/data
    selinux          feature/selinux/data
    customrom        feature/customrom/data
    kernelcheck      feature/kernelcheck/data
    systemproperties capability/systemproperties/data
    bootloader       feature/bootloader/data
    mount            feature/mount/data
    preload          capability/earlypreload/data
    memory           feature/memory/data
    playintegrityfix feature/playintegrityfix/data
    nativeroot       feature/nativeroot/data
    lsposed          feature/lsposed/data
    zygisk           feature/zygisk/data
    virtualization   capability/helperprocess/data
)

cmake_path(SET repository_root NORMALIZE "${CMAKE_CURRENT_SOURCE_DIR}/../../../../..")
set(duckdetector_units "")
set(duckdetector_unit_dirs "")
# Units include each other by unit directory, such as "common/payload_codec.h", so the source
# directory of every owning module is an include directory.
set(DUCKDETECTOR_NATIVE_INCLUDE_DIRS "")
list(LENGTH DUCKDETECTOR_NATIVE_UNITS unit_values)
math(EXPR last_unit_value "${unit_values} - 1")
foreach(unit_index RANGE 0 ${last_unit_value} 2)
    math(EXPR owner_index "${unit_index} + 1")
    list(GET DUCKDETECTOR_NATIVE_UNITS ${unit_index} unit)
    list(GET DUCKDETECTOR_NATIVE_UNITS ${owner_index} owner)
    list(APPEND duckdetector_units ${unit})
    list(APPEND duckdetector_unit_dirs "${repository_root}/${owner}/src/main/cpp/${unit}")
    list(APPEND DUCKDETECTOR_NATIVE_INCLUDE_DIRS "${repository_root}/${owner}/src/main/cpp")
endforeach()
list(REMOVE_DUPLICATES DUCKDETECTOR_NATIVE_INCLUDE_DIRS)

# Each native unit is an object library linked into libduckdetector.so.
function(duckdetector_native_unit target)
    add_library(${target} OBJECT ${ARGN})
    set_property(TARGET ${target} PROPERTY POSITION_INDEPENDENT_CODE ON)
    if(ipo_supported)
        set_property(TARGET ${target} PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
    endif()
    # Warnings stay warnings rather than errors: the probes deliberately do unusual things with
    # syscalls and raw memory, so a blanket -Werror would block builds on diagnostics that need
    # to be judged case by case. Surfacing them is the point.
    target_compile_options(${target} PRIVATE
        $<$<COMPILE_LANGUAGE:C,CXX>:-Wall -Wextra>
        $<$<AND:$<CONFIG:Release>,$<COMPILE_LANGUAGE:C>>:-O2 -ffunction-sections -fdata-sections -fvisibility=hidden>
        $<$<AND:$<CONFIG:Release>,$<COMPILE_LANGUAGE:CXX>>:-O2 -ffunction-sections -fdata-sections -fvisibility=hidden -fvisibility-inlines-hidden>
    )
    target_include_directories(${target} PRIVATE
        ${DUCKDETECTOR_NATIVE_INCLUDE_DIRS}
    )
endfunction()

foreach(unit unit_dir IN ZIP_LISTS duckdetector_units duckdetector_unit_dirs)
    add_subdirectory(${unit_dir} units/${unit})
endforeach()

add_library(duckdetector SHARED)
set_property(TARGET duckdetector PROPERTY LINKER_LANGUAGE CXX)
if(ipo_supported)
    set_property(TARGET duckdetector PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
endif()

target_link_options(duckdetector PRIVATE
    $<$<CONFIG:Release>:-Wl,--gc-sections>
)

list(TRANSFORM duckdetector_units PREPEND duckdetector_ OUTPUT_VARIABLE duckdetector_unit_targets)
target_link_libraries(duckdetector PRIVATE
    ${duckdetector_unit_targets}
    android
    EGL
    GLESv2
    log
    mediandk
)

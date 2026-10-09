# System Properties evidence record

Status: reviewed

The System Properties detector asks whether security-relevant properties describe a debug, unlocked or modified build, and whether property sources disagree in a way that suggests rewriting.

## Signals

### Security property catalog

- Observable signal: build type and tags, debuggable and secure flags, encryption state, OEM unlock state, custom ROM version properties, and Build.TYPE, Build.TAGS and Build.FINGERPRINT against the matching properties.
- Producing subsystem: init's property service and the build's property files.
- Mechanism: user builds set fixed values for these properties; debug builds, unlocked devices and custom ROMs differ.
- References: system/core init/property_service.cpp; frameworks/base services/core/java/com/android/server/pdb/PersistentDataBlockService.java (sets sys.oem_unlock_allowed at android-15.0.0_r1, no longer at android-16.0.0_r1).
- Applicability: sys.oem_unlock_allowed is expected only through Android 15; any value from Android 16 was written by something other than AOSP.
- Visibility limits: properties whose context apps may not read return empty.
- Result states: danger, warning, info, clean.
- Interpretation: each rule's severity reflects what the value shows; a custom ROM property is a finding about the build.

### Source consistency

- Observable signal: the same property read through android.os.SystemProperties, getprop, System.getProperty and native __system_property_get.
- Producing subsystem: bionic's property area, the framework wrapper, and the getprop tool.
- Mechanism: a module that hooks one read path, or resets a property after boot, leaves sources in disagreement.
- References: bionic libc/include/sys/system_properties.h; frameworks/base core/java/android/os/SystemProperties.java; capability/systemproperties/EVIDENCE.md.
- Applicability: every release.
- Visibility limits: getprop runs with this app's own permissions.
- Result states: mismatch, consistent, unavailable.
- Interpretation: a disagreement is evidence of rewriting.

### Raw boot parameters and property area layout

- Observable signal: androidboot.* in /proc/cmdline and /proc/bootconfig, and holes in the /dev/__properties__ areas.
- Producing subsystem: the bootloader's command line and bionic's property areas.
- Mechanism: init imports androidboot.* as ro.boot.*; resetprop-style tools rewrite property areas and can leave holes.
- References: system/core init/property_service.cpp (bootconfig and cmdline import); bionic libc/include/sys/system_properties.h. Discovery only for the property area hole heuristics.
- Applicability: bootconfig on Android 12 and later kernels.
- Visibility limits: /proc/cmdline and bootconfig are often unreadable for apps.
- Result states: mismatch, hole found, consistent, unavailable.
- Interpretation: holes and raw-versus-runtime mismatches are danger or warning by rule.

### Property area modification times

- Observable signal: the lstat modification times of the debug_prop, radio_prop and system_prop property-area files, recorded as a diagnostic.
- Producing subsystem: init's property service and bionic's property areas on the /dev tmpfs, together with the kernel's write-fault path for shared file mappings.
- Mechanism: init creates one area file per context, maps it MAP_SHARED and writes properties as stores to that mapping, never with write(2). tmpfs has no page_mkwrite, so the kernel updates the file's mtime only when a process takes a write fault on such a mapping, typically its first store to a page not yet mapped in it, or to one whose mapping was torn down since; rewriting an existing property in place usually leaves the mtime alone. The time is the coarse, tick-granular wall clock, which can still read near 1970 early in boot and is stepped later. init creates the files in property_info's sorted context order (debug, radio, system), so creation order alone does not make debug newer than radio.
- References: bionic libc/system_properties/prop_area.cpp (map_prop_area_rw) and contexts_serialized.cpp; system/core property_service/libpropertyinfoserializer/trie_builder.h (contexts kept in a sorted set); kernel/common mm/memory.c (fault_dirty_shared_page), mm/shmem.c (shmem_vm_ops) and fs/inode.c (current_time); frameworks/base services/core/java/com/android/server/SystemClockTime.java (initializeIfRequired, for a boot clock "like 1970-01-01"); system/sepolicy public/property.te and private/property.te (core_property_type), private/domain.te and public/te_macros (get_prop).
- Applicability: API 29 and later. bionic and the policy read the same at android-10.0.0_r1 and AOSP main, and the fault path is the same in ACK deprecated/android-4.19-stable, android11-5.4 and android15-6.6; vendor kernels were not checked.
- Visibility limits: the three types carry core_property_type, which AOSP policy lets appdomain read, getattr included. A vendor policy that denies it, a missing file and a non-regular file are recorded for that file with the errno or reason, and show no time.
- Result states: one informational row under the detection methods with each file's UTC mtime, its lstat errno, or "not a regular file". It never changes the card's status, verdict or review count.
- Interpretation: none. No tool or modification is known to leave a particular order: a normal boot can stamp the radio area before the clock is set while the debug and system areas take later faults, and root can rewrite any of these times with utimensat. The times are kept so that devices can be compared; scoring them needs a mechanism-backed hypothesis and data from stock and modified devices.

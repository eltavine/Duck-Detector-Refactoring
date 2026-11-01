# Early preload capability evidence record

Status: reviewed

The early preload capability captures mount and virtualization evidence in the transparent NativeActivity before the activity it launches starts, and hands it to the Mount and Virtualization detectors. It supplies an earlier observation point; launch timing does not establish whether hiding has already happened.

## Signals

### Early mount view

- Observable signal: mountinfo and mntent state at launch, including mount ID gaps, peer group gaps, minor device gaps and futile hide markers.
- Producing subsystem: the kernel's mount tables for the app's namespace, read by the NativeActivity before the launched activity starts.
- Mechanism: a hiding module that unmounts or rewrites entries after launch leaves the early view different from the later one.
- References: kernel/common Documentation/filesystems/proc.rst section 3.5 (mountinfo mount IDs, propagation and peer groups).
- Applicability: only when the app starts through the NativeActivity launcher; SDK hosts without it report the capture unavailable.
- Visibility limits: a capture older than the current process context is marked stale.
- Result states: captured, stale, not run.
- Interpretation: consumers merge the early findings with their runtime scan. Mount ID discontinuities are INFO observations only: ACK uses a global reusable mount ID allocator, and mountinfo lists this namespace rather than a consecutive ID sequence. The startup and runtime collectors use the same `common/mount_id_observation.h` policy; repeated captures do not supply independent corroboration or promote severity. Existing signal keys remain compatible, but mount ID observations do not contribute to `hasDangerSignal`. Historical native/intent records are normalized to INFO without discarding their detail.
- Sources and limits: [Mount ID evidence and pinned ACK/AOSP references](../../feature/mount/EVIDENCE.md#mount-id-discontinuities). Android 14 app data isolation legitimately uses `/data_mirror`; its presence does not identify a hiding mechanism. The inspected branches do not reconstruct the provenance of specific IDs on an unspecified device. Synthetic native and Kotlin regression cases cover interval sizes and risk propagation; real device snapshots remain necessary for device-specific attribution.

### Early virtualization view

- Observable signal: emulator properties, device nodes and translation markers at launch.
- Producing subsystem: init's property service and the kernel's device nodes.
- Mechanism: the same probes as the Virtualization detector run before a host framework can adjust the process.
- References: system/core init/property_service.cpp; frameworks/base core/jni/AndroidRuntime.cpp (native bridge property).
- Applicability: as for the early mount view.
- Visibility limits: the preload matches finding labels produced by the virtualization native unit, a text protocol recorded in docs/architecture/follow-ups.md.
- Result states: captured, stale, not run.
- Interpretation: consumers compare the early and runtime views.

Mount ID, peer group and anonymous-device identifiers are globally allocated and reusable; proc inode ctime reflects inode creation/state rather than a mount event. These startup observations normalize to INFO, including legacy records, and cannot contribute to danger or warning. Only the specific mntent root source/path marker currently contributes to `hasDangerSignal`; `/data/adb` path matches require a path-component boundary. The parser rejects malformed/overflowing numbers without throwing, and peer group counting stores observed identifiers rather than allocating a bitmap indexed by the largest global ID. See the linked Mount evidence record for the inspected ACK functions, platform counterexamples, and injected-I/O regressions.

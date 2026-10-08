# Native Root evidence record

Status: reviewed

The Native Root detector asks whether kernel-level root solutions (KernelSU and its forks, APatch or KernelPatch, Magisk) leave evidence an ordinary app can observe. Findings are evidence of root tooling; their absence does not prove a device is unrooted.

## Signals

### KernelPatch supercall probes

- Observable signal: whether syscall 45 reads its first argument before the truncate body rejects a negative length (superkey residency), and the timing gap between a long and an empty key (pre-84169d5d builds).
- Producing subsystem: the arm64 kernel syscall table, which KernelPatch patches.
- Mechanism: a stock kernel rejects the negative length in do_sys_truncate before deriving a user pointer, so an untouched page stays non-resident; KernelPatch's handler reads arg0 first and faults it in.
- References: kernel/common fs/open.c (do_sys_truncate rejects a negative length before any path lookup). Discovery only for KernelPatch's handler order, which follows the probe authors' reading of KernelPatch.
- Applicability: arm64 processes only; the negative superkey result is trusted only on kernels up to 6.6, where KernelPatch's read faults the page.
- Visibility limits: seccomp can block syscall 45 in the child; other ABIs use another syscall numbering and report the probes as not run.
- Result states: detected, clean (arm64, measured), unavailable (other ABI, blocked, unmeasured, unusable run).
- Interpretation: a residency hit is conclusive on any version; everything short of a measured run is Unavailable.

### Netlink permission boundary

- Observable signal: whether RTM_GETLINK or RTM_GETNEIGH dumps are answered, and whether they expose a physical MAC or a LAN neighbour.
- Producing subsystem: SELinux's netlink_route_socket checks in the kernel and the loaded policy.
- Mechanism: ACK requires nlmsg_readpriv and nlmsg_getneigh when the policy carries Android's netlink config bits; untrusted app domains are denied them.
- References: kernel/common security/selinux/nlmsgtab.c (android11-5.4 through android15-6.6); external/selinux libsepol/src/write.c at android-11.0.0_r1 through android-14.0.0_r1; system/sepolicy app_neverallows.te and untrusted_app_25/27/29/30.te at android-11, 12 and 13 and main; platform/cts tests/tests/selinux/common SELinuxTargetSdkTestBase.java.
- Applicability: RTM_GETLINK is denied from Android 11 to apps targeting SDK 30 or later and from Android 13 to every untrusted app; RTM_GETNEIGH is denied only from Android 13 to apps targeting SDK 32 or later.
- Visibility limits: the check is skipped where the denial does not apply to this process, which the target SDK of an SDK host decides.
- Result states: enforced, not enforced, not applicable, not evaluated.
- Interpretation: an answered request that exposes hardware addresses is a DANGER finding about the boundary, without attributing it to a particular root solution.

### KernelSU interfaces

- Observable signal: the KernelSU prctl magic, the read-only supercall through a sacrificial child, [ksu_driver] and [ksu_fdwrapper] descriptors, the su SELinux domain, and devpts labels.
- Producing subsystem: KernelSU's kernel module or built-in patches.
- Mechanism: KernelSU answers its own prctl option and installs its driver through the reboot magic, and labels su PTYs as ksu_file.
- References: Discovery only: these interfaces follow KernelSU's behaviour as implemented by the probes; KernelSU's source was not reviewed in this pass.
- Applicability: KernelSU and forks that keep these interfaces.
- Visibility limits: KernelSU hides most interfaces from apps it does not grant; seccomp can block the helper's reboot call.
- Result states: detected, clean, blocked, unavailable.
- Interpretation: direct interface answers are DANGER; a blocked or unattempted probe reduces coverage.

### SUSFS setresuid side channel

- Observable signal: how the kernel answers a child's setresuid to a lower uid.
- Producing subsystem: the kernel's credential checks and any SUSFS or KernelSU hook on them.
- Mechanism: bionic's app seccomp filter allows setresuid, so the call reaches the kernel, which returns EPERM to an unprivileged app; old SUSFS hooks kill the child instead.
- References: bionic libc/SECCOMP_BLOCKLIST_APP.TXT and libc/seccomp/seccomp_policy.cpp.
- Applicability: every ABI; regular app processes, not app zygote children.
- Visibility limits: fork or waitpid can fail, which leaves the result not observed.
- Result states: denied, killed, UID changed, not observed.
- Interpretation: SIGKILL and a successful UID change are DANGER; only a denial is Normal.

### Root solution paths and temp root artifacts

- Observable signal: root manager paths, residue paths and temp root tooling in /data/local/tmp.
- Producing subsystem: the filesystem as seen through DAC and SELinux.
- Mechanism: root solutions keep their files in fixed locations, and public temp-root tools stage their payloads in /data/local/tmp.
- References: system/core rootdir/init.rc (AOSP never creates /data/adb); system/sepolicy private/file_contexts (/data/adb is adb_data_file) and private/untrusted_app_all.te (apps may stat shell_data_file); NVD CVE-2026-43499 for the GhostLock tooling names.
- Applicability: every release; /data/adb exists only where a root solution or userdebug adbd created it.
- Visibility limits: a path whose parent this app cannot search is not observable; such rules are reported, not counted as checked.
- Result states: present, absent, not observable.
- Interpretation: present paths are findings at their catalog severity; unobservable paths reduce coverage to SUPPORT.

### Process, cgroup, mount namespace and kernel traces

- Observable signal: suspicious processes, per-UID cgroup trees that disagree with the Java view, mount namespace drift between the app and an isolated helper, and root tokens in kallsyms, modules, uname or properties.
- Producing subsystem: procfs and cgroupfs, the mount namespace set up by zygote, and the kernel's exported symbol tables.
- Mechanism: root solutions run daemons, give processes distinct mount namespaces, and leave kernel symbols or properties with recognisable names.
- References: kernel/common Documentation/filesystems/proc.rst (status, mountinfo, ns); frameworks/base core/jni/com_android_internal_os_Zygote.cpp for zygote's per-app mount setup. Discovery only for the token catalogs.
- Applicability: every release; kallsyms addresses and modules are usually hidden from apps.
- Visibility limits: /proc of other UIDs is normally denied; denied entries are counted, not read as clean.
- Result states: detected, clean, limited, unavailable.
- Interpretation: kernel and process tokens are indirect evidence and never outweigh a direct probe.

### KernelSU manager scans and shell tmp metadata

- Observable signal: the throne hunt, which is an inotify watch on this package's directory installed from app_zygote while packages.list is rewritten; the public manager manifest under the KernelSU package name; and the owner, mode and inode of /data/local/tmp.
- Producing subsystem: KernelSU's throne tracker, PackageManager's mime group path, and the filesystem.
- Mechanism: setMimeGroup makes system_server rewrite packages.list, KernelSU's manager tracker then walks package directories, and the inherited watch sees that walk; a changed shell tmp owner or mode shows the directory was recreated.
- References: frameworks/base core/java/android/content/pm/PackageManager.java (setMimeGroup); frameworks/base services/core/java/com/android/server/pm/PackageManagerService.java (setMimeGroup rejects a group the package does not declare, then schedules the settings write that rewrites packages.list; Android 11 through main); frameworks/base core/java/com/android/internal/pm/parsing/pkg/PackageImpl.java (a package declares the MIME groups of every component's intent filters, services included; ParsingPackageImpl before Android 14); system/core rootdir/init.rc (/data/local/tmp is created shell:shell); frameworks/base core/jni/fd_utils.cpp (FileDescriptorInfo::CreateFromFd aborts a fork on an open descriptor that is not a socket, regular file or character device, such as an inotify descriptor; Android 11 through main); frameworks/base core/java/com/android/internal/os/AppZygoteInit.java and core/jni/com_android_internal_os_Zygote.cpp (doPreload runs between Zygote.markOpenedFilesBeforePreload and allowFilesOpenedByPreload, and the descriptors it opened join every fork's fds_to_ignore; Android 12 through main). Discovery only for the throne tracker's traversal and the manager manifest traits.
- Applicability: the throne hunt needs Android 12 or later, where app_zygote exempts the descriptors its preload opens from the fork check, and this package's directory to be watchable from app_zygote. On Android 11 the watch is not installed, because an open inotify descriptor would abort every app_zygote fork.
- Visibility limits: a denied watch, an unapplied stimulus or restricted package visibility reduce coverage; a high inode alone is weak. The throne hunt carrier shares this package's app zygote with the SELinux carrier, so after either is stopped before it connected, the other is not started in that scan and the round is unavailable.
- Result states: detected, clean, limited, unavailable.
- Interpretation: a traversal hit is danger; manifest traits are auxiliary; shell tmp owner or mode drift is a warning.

### Experimental fsnotify SRCU close timing

- Observable signal: repeatedly elevated whole-instance inotify close latency in candidate-overlap windows of a synchronous dynamic-permission update, relative to both idle and post-update sequential controls.
- Producing subsystem: ACK fsnotify mark destruction, the global `fsnotify_mark_srcu` reader domain, and Android's legacy permission/settings persistence path.
- Mechanism: closing an inotify instance with a mark destroys its group, flushes the mark reaper and waits for a global SRCU grace period. A long-lived reader elsewhere can delay the app's close. Legacy synchronous `addPermission` changes write PackageManager settings, including packages.list; the reader used by old KernelSU's package observer could scan synchronously within that domain. User-space Binder windows establish candidate overlap only.
- References: [PackageManager public API](https://developer.android.com/reference/android/content/pm/PackageManager#addPermission(android.content.pm.PermissionInfo)); AOSP permission, settings and backend sources and five pinned ACK branch revisions in [the design and validation record](SRCU_TIMING.md). KernelSU [ab23091e](https://github.com/tiann/KernelSU/commit/ab23091edfeddc774e1e880b0919b211808a193e) defers normal scans to task_work outside SRCU; [6b5f55bd](https://github.com/tiann/KernelSU/commit/6b5f55bd95e9c412bafd1dbe1431032cd32baa20) removes the manager-absent full scan. These commits narrow the hypothesis rather than establish a positive signature.
- Applicability: explicit consent only, default disabled; Android 12–14 (API 31–34) legacy backend, because Android 11 stores the tree's record and its readback cannot confirm a change; reviewed kernel families 5.10, 5.15, 6.1, 6.6 and 6.12; all four supported ABIs, using CLOCK_MONOTONIC rather than architecture registers. Kernel release is a conservative admission gate, not verification of vendor behavior.
- Visibility limits: no direct observation of packages.list, the kernel reader, its identity, or its lifetime. OEM backend changes, sandbox denials, unrelated readers, PackageManager load, CPU scheduling and concurrent SDK scans can defeat interpretation. Latest KernelSU normally eliminates the hypothesized reader; inline failure fallbacks and forks remain possible. The known pre-fix lock inversion can stall system_server or the kernel; a private-process watchdog bounds host waiting but cannot recover either. Cleanup after process death is unconfirmed.
- Result states: not requested; unsupported Android/kernel; unavailable permission tree/name; native, trigger, cleanup or IPC failure; busy; timed out; collected but inconclusive; delay not observed; repeatable delay. All samples retain timestamps, stage and errno; failed native windows remain diagnostic evidence. Too few overlap samples, a quota hit or an invalid control is inconclusive.
- Interpretation: 12 complete randomized three-arm rounds, at least eight overlap samples per arm, a scale-relative p95 gap in 10 rounds with replication across each four-round block, and stable controls produce an experimental WARNING about contention. This is not direct root evidence, does not set any root-family identity, and cannot produce DANGER. Thresholds await device calibration. Negative or unavailable timing cannot exclude KernelSU and never supplies All Clear on its own. An unsupported Android or kernel leaves Native Root coverage unchanged; an applicable run that fails or stays inconclusive reduces it.

## Known gaps

- The KernelSU interface probes and the kernel token catalogs rest on tool behaviour, not on a reviewed tool source.
- The devpts check treats a root-owned PTY as root evidence, which userdebug builds also produce.

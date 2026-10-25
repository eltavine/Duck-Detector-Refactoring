# Zygisk evidence record

Status: reviewed

The Zygisk detector asks whether code injected through zygote (Zygisk, Zygisk Next, ReZygisk, NeoZygisk) left traces in this app process. Strong traces point at injection; heuristic traces need corroboration.

## Signals

### Linker and namespace integrity

- Observable signal: whether dlopen, dlsym and dlclose resolve into the loader image, whether their entries branch straight out of it, and whether restricted-path libraries are loaded.
- Producing subsystem: the dynamic linker and this process's linker namespaces.
- Mechanism: injection frameworks hook the loader's entry points or load libraries from paths the app's namespace should not reach.
- References: bionic linker/linker_namespaces.h (is_accessible and isolated namespaces); kernel/common Documentation/filesystems/proc.rst for /proc/self/maps. Discovery only for the restricted path list.
- Applicability: the owning-image check on every ABI; the branch decoding on arm64 only.
- Visibility limits: an unreadable /proc/self/maps leaves the snapshot unavailable.
- Result states: bypassed, clean, unavailable.
- Interpretation: a linker hook or namespace bypass is a strong hit and danger.

### Memory map families

- Observable signal: suspicious executable mappings, deleted loaders, JIT cache drift, dirty system library pages, solist drift, atexit routing and heap entropy.
- Producing subsystem: this process's address space and the linker's soinfo list.
- Mechanism: an injected library that later unloads or hides still leaves mapping, dirty page or allocator residue.
- References: kernel/common Documentation/filesystems/proc.rst (maps and smaps fields). Discovery only for the per-framework residue patterns.
- Applicability: every ABI; heap entropy only where jemalloc state is readable.
- Visibility limits: each family is a heuristic with known benign causes.
- Result states: strong hit, heuristic hit, clean, unavailable.
- Interpretation: one heuristic family is a warning; multiple families escalate to danger for review, but do not establish injection. Loader-path residue seen through maps and descriptors is one family even when multiple files or descriptors match. JIT mapping structure, solist visibility, atexit ownership, dirty system code, thread names and heap entropy retain separate family identities. Different family identities do not prove statistical independence or exclude benign causes.

### Threads, descriptors and FD trap

- Observable signal: TracerPid, thread names, open descriptor targets, and whether a descriptor planted before fork is closed by an injection stack.
- Producing subsystem: procfs and zygote's fork path.
- Mechanism: Zygisk closes or reopens descriptors around specialization, and tracing tools set TracerPid.
- References: kernel/common Documentation/filesystems/proc.rst (status TracerPid, fd); frameworks/base core/jni/com_android_internal_os_Zygote.cpp for the specialization path. Discovery only for the FD trap's Zygisk-specific expectation.
- Applicability: the FD trap is skipped under a debugger or profiling agent.
- Visibility limits: debuggers and agents legitimately change descriptors and TracerPid. A detector binding the system stops before it connects, as it does to every service of the package when another of its processes fails to start, is bound once more; a second stop leaves the FD trap unavailable.
- Result states: FD trap hit, heuristic hit, clean, skipped.
- Interpretation: an FD trap hit is danger; thread and descriptor names are heuristics.

## Installed package paths and correlated residue

- Reference: [PackageManagerServiceUtils.getNextCodePath](https://android.googlesource.com/platform/frameworks/base/+/d1b7893669c02d6dc95c75133fa01eedc1d9fec6/services/core/java/com/android/server/pm/PackageManagerServiceUtils.java) uses two random 16-byte URL-safe Base64 installation tokens. Their characters are not evidence of an injection framework. Keyword classification shares the installed-path parser with Memory; evidence retains its original path and no WebView package is exempted.
- Regression: issue #400's WebView path contains `Riru` in the random suffix. Its APK/ODEX mappings and open APK descriptors must not produce a keyword hit. A real loader-path hit visible in both maps and FDs produces two diagnostic traces but only one heuristic family. Independent non-path mechanisms can still add families; direct strong hits and the FD trap keep their existing grading.
- Verification: `python3 feature/zygisk/data/src/test/python/test_loader_path_host_native.py` runs the production map and FD classifiers and family aggregation against synthetic fixtures. It covers ordinary WebView paths, real framework names, deleted libraries, non-executable mappings, repeated descriptors and independent JIT/atexit evidence. A device-specific reproduction still needs the exact WebView version and raw mapping/loader inventory.

The FD collector constructs the complete `/proc/self/fd/` path with a string instead of formatting into a fixed-capacity buffer. Valid descriptor lookup and loader-path interpretation are unchanged; a truncated path is never queried. The existing host-native suite compiles this collector with warnings treated as errors.

## Libc exit-handler table semantics

The question is whether this process retains exit-handler references or ordered null runs consistent with a library that was injected through zygote and then unloaded. This is corroborating evidence, not a framework identity or an integrity guarantee.

- Bionic Android 11 through 17 defines each entry as a callback, argument and DSO handle. The private array records its pointer, size, extracted count, capacity and append count. `__cxa_finalize` zeros extracted entries; recompaction is conditional on releasing a page, so normal library finalization can leave holes. References: [Android 11 atexit.cpp](https://android.googlesource.com/platform/bionic/+/android-11.0.0_r1/libc/bionic/atexit.cpp), [Android 16 atexit.cpp](https://android.googlesource.com/platform/bionic/+/android-16.0.0_r1/libc/bionic/atexit.cpp), [Android 17 atexit.cpp](https://android.googlesource.com/platform/bionic/+/android-17.0.0_r1/libc/bionic/atexit.cpp).
- Table reads must coordinate with Bionic's private atexit mutex. A busy or missing lock, an absent local symbol table, unknown layout, invalid counts or a failed read is unavailable/unsupported evidence, never a negative result. A reader must neither call unrelated destructors nor rewrite or compact libc state.
- The visibility boundary is this app's loaded libc and its own address space. The tested AVD kernel identifies ACK revision `d0c43a640eab` (6.6.66, Android 15 branch). Although [mm_access](https://android.googlesource.com/kernel/common/+/d0c43a640eab/kernel/fork.c) permits the same address space, [task_dump_owner](https://android.googlesource.com/kernel/common/+/d0c43a640eab/fs/proc/base.c) changes proc-file ownership for non-dumpable processes. Opening `/proc/self/mem` can therefore fail with EACCES in a normal non-debuggable app. The collector instead copies its own readable pages through a private nonblocking pipe: [pipe_write](https://android.googlesource.com/kernel/common/+/d0c43a640eab/fs/pipe.c) uses [copy_page_from_iter/copyin](https://android.googlesource.com/kernel/common/+/d0c43a640eab/lib/iov_iter.c), reporting bad source pages as a failed/partial write rather than a userspace dereference fault. Each chunk is at most the ACK [PIPE_BUF of 4096 bytes](https://android.googlesource.com/kernel/common/+/d0c43a640eab/include/uapi/linux/limits.h), drained before the next write. SELinux/OEM restrictions remain a runtime coverage boundary. No process dumpability, permission or label is changed; no other process's memory, root-only module directory or shell grant is involved.
- Local ELF objects are a private implementation dependency, not an Android API. [ELF symbol semantics](https://gabi.xinuos.com/elf/05-symtab.html) establish symbol type, section index, value and size; stripped local symbols or incompatible layouts reduce coverage.
- Sample provenance: Zygisk Next `1.5.2 (864-a4a72ce-release)`, supplied ZIP SHA-256 `ce50b13fecb9e4456db69ef17b715f7cfbc094004dd9f30f7d6348dfab619a96`. Its arm64 loader imports `__cxa_atexit` and `__cxa_finalize`; imports alone do not establish that a particular callback or gap survives specialization. No sample code or binary is incorporated.
- [ReZygisk b5aa415](https://github.com/PerformanC/ReZygisk/tree/b5aa415c2ce1161ab807578ce0414129fbfc6313) unloads modules through its custom loader. [NeoZygisk d161f31](https://github.com/JingMatrix/NeoZygisk/tree/d161f31c9cfa5307366d0d15f2cbcea61cd0e3ce) blocks loader-local atexit registration and explicitly attempts to compact the libc table and rewind counters. These mechanisms are false-negative conditions; an absence of residue cannot exclude either framework. The implementations are research references; their code is not reused.
- Discovery provenance: the supplied zDefend rule `zygisk_atexit_soinfo` v12 exposes library-relative gap and callback mapping checks. Its native collector is not available as source. Its inferred function names and version branches are not platform contracts and are not copied as implementation.

### Implementation and interpretation

The reader inspects only the loaded libc file and this process's memory. A bounded native-class ELF symbol-table reader resolves the monolithic array or each of the five split local objects independently, and the exact atexit lock object; it validates object type, allocated writable section, size, arithmetic, mapping coverage and metadata counts. There is no instruction decoding, copied SDK collector, guessed address, compressed-debug-data fallback or added runtime dependency. The limited ELF read uses the platform's `<elf.h>` definitions rather than introducing a general ELF editing/disassembly dependency for these objects. Android 10 and releases newer than the reviewed Android 17 layout are explicitly unsupported. Missing local symbols remain unsupported on otherwise valid stripped ELF images.

Collection creates the private pipe and preallocates a 65536-entry buffer, tries the private mutex once, copies through bounded pipe writes/reads and releases the lock before allocation, logging or path interpretation. It does not register calibration handlers, invoke destructors, compact tables, alter memory protections or rewrite handler entries/counters. Standard pthread operations update only the lock metadata needed for synchronization. Mutex contention is busy; permission failures are permission limited; malformed metadata, failed reads and missing application bounds stay distinguishable. Callback owners must match in mapping samples before and after collection; changed/unmapped owners reduce coverage. This does not make arbitrary concurrent loader changes atomic. [PR_GET_DUMPABLE](https://android.googlesource.com/kernel/common/+/d0c43a640eab/kernel/sys.c) is recorded as read-only context to distinguish debug-only coverage from a non-dumpable app test.

Only fully zeroed entries count as finalization holes. Nonzero entries with inaccessible callback mappings are not fabricated holes. The search ends at application-owned registrations or a validated perfetto sequence. Runs of at least three zero entries near libadbconnection/libwilhelm, after sixteen consecutive libart-owned registrations, or before a validated perfetto pair produce warning evidence. Memfd and selected anonymous executable callback owners before the application boundary also produce warning evidence; callback arguments pointing into anonymous data and named anonymous ART JIT mappings such as `[anon:dalvik-jit-code-cache]` do not. These are deliberately narrower interpretations than treating every invalid DSO as an injection residue. Normal system-library unloads, profiling and legitimate pre-application memfd callbacks remain possible benign causes.

All new hits remain in one atexit heuristic family, alongside existing atexit ownership evidence. None alone is a direct/danger hit or a Zygisk Next version identification. The existing cross-family grading is unchanged. Table coverage and counts have a typed native/domain result, a dedicated report method and escaped payload fields. Unknown or missing coverage never defaults to evaluated, and an incomplete table prevents an otherwise empty report from being all-clear.

Host fixtures cover clean/app-local/leading/short gaps, runtime anchors, unmapped callbacks, anonymous arguments, named JIT mappings and retained heuristic severity. ELF fixtures cover split objects, duplicate/conflicting symbols, stripped headers, wrong class, invalid bounds, arithmetic overflow and missing locks. Memory-copy fixtures cover multiple pipe chunks, unreadable pages, address overflow, poisoned-reader reuse and unchanged non-dumpable state on Linux/Android. The ordinary-UID AVD fixture is owned by the feature and assembled into host instrumentation to use the actual shipped collector. Runtime commands, input hashes and comparisons are recorded in [the AVD comparison](research/atexit/README.md).

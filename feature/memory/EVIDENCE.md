# Memory evidence record

Status: reviewed

The Memory detector asks whether this process's own code and mappings show signs of in-process hooking or injected code. Findings describe this process only.

## Signals

### Symbol resolution and entry prologues

- Observable signal: where dlsym resolves sensitive libc and linker symbols, the first bytes at those entry points, and where a direct branch there lands.
- Producing subsystem: the dynamic linker and the mapped libc and linker images in this process.
- Mechanism: a PLT or GOT hook resolves the symbol outside its module; an inline hook replaces the prologue with a branch or a load-and-branch trampoline that hands execution to code outside the module's image. libdl's entry points that pass the loader no caller address, dlclose among the targets, only forward to the loader's weak __loader_* symbols. Clang tail-calls those on x86_64, so the entry is a jmp into libdl's own PLT; AArch64 never tail-calls an extern_weak callee, so there the same forwarders keep a frame and a bl.
- References: kernel/common Documentation/filesystems/proc.rst for /proc/self/maps; bionic linker/linker_namespaces.h for the loader's namespaces; bionic libdl/libdl.cpp for the forwarders; LLVM lib/Target/AArch64/AArch64ISelLowering.cpp, whose isEligibleForTailCallOptimization refuses extern_weak callees under the AAELF64 rule for calls to undefined weak functions. Discovery only for the prologue byte patterns, which are the probe's instruction heuristics.
- Applicability: resolution checks on every ABI; entry byte checks only on arm64 and x86_64.
- Visibility limits: dlopen(nullptr) can fail; other ABIs report the entry check as unsupported. A direct branch that lands in executable code of the image holding the entry, the run of adjacent mappings of one system file, reads as a forwarder, so a hook that relays through a cave inside that image is not seen here; writing the cave makes a private copy of its page, which the mappings signal below reports as privately copied system code. The GOT slot that a forwarder's PLT entry jumps through is not checked.
- Result states: mismatch, hook-like, jump entry, clean, unavailable, unsupported ABI.
- Interpretation: an escaped symbol, or a branch prologue that leaves its image, is danger; a trampoline-style entry alone is review; an entry that branches within its own system image is clean.

### Mappings, file-backed code and loader visibility

- Observable signal: writable or anonymous executable mappings, privately copied executable system pages and whether their bytes still match the file, shared-dirty or swapped executable system pages, executable memfd, ashmem, deleted libraries or /dev/zero, modules visible to maps but not to dl_iterate_phdr, and a remapped or unusually based [vdso].
- Producing subsystem: the kernel's view of this process's address space.
- Mechanism: injected code usually needs anonymous or writable executable memory or hides its loader entry, and code patched in place turns each page it writes into a private copy. A read can make the same private copy without changing it, so the detector compares the copied page's bytes with the file.
- References: kernel/common Documentation/filesystems/proc.rst (maps and smaps fields such as Private_Dirty, Swap and Anonymous, which in a MAP_PRIVATE file mapping counts the pages replaced by private copies, and the [vdso] mapping); kernel/common Documentation/admin-guide/mm/pagemap.rst (pagemap bit 63 present, bit 62 swapped and bit 61 file-page or shared-anon, and that only CAP_SYS_ADMIN reveals the frame number, not these flags); kernel/common ASB-2021-05-05_4.19-stable fs/proc/task_mmu.c and mm/gup.c (seq_print_vma_name pins the page holding each anonymous VMA name with get_user_pages_remote, and should_force_cow_break, the CVE-2020-29374 workaround, turns every pinning lookup on a MAP_PRIVATE mapping into a write fault, which copies a file page; pagemap_read walks the page tables without pinning); chromium build/config/compiler/BUILD.gn and partition_alloc page_allocator_internals_posix.cc (Android builds link with --no-rosegment, which keeps .rodata in the executable segment, and PartitionAlloc names its anonymous mappings with .rodata literals); bionic linker/linker_phdr.cpp, linker/linker.cpp and linker/linker_relocate.cpp (the loader maps load segments with their final protection and makes executable ones writable only for text relocations, which it refuses in 64-bit processes and in 32-bit apps targeting API 23 or later); kernel/common arch/arm64/kernel/vdso.c and arch/arm64/include/asm/elf.h (AArch64 processes always get a vDSO and AT_SYSINFO_EHDR, 32-bit processes only with CONFIG_COMPAT_VDSO); bionic libc/bionic/vdso.cpp (no AT_SYSINFO_EHDR means no vDSO).
- Applicability: every ABI and release; the [vdso] checks need a vDSO, which the kernel does not map for 32-bit processes on arm64 kernels without CONFIG_COMPAT_VDSO, on arm kernels without CONFIG_VDSO, or on x86 kernels with it disabled.
- Visibility limits: ART's JIT legitimately creates anonymous executable code; the repository removes that known case. For a privately copied page of an executable system mapping the detector reads the page through a pipe, whose write pins nothing, and compares it with the file at the mapping's offset, after confirming through the mapping's device and inode that the path still names the mapped file; process_vm_readv and /proc/self/mem are avoided because on kernels with the forced COW break they would copy the very page they read. A copy equal to the file is benign, but equality only shows the bytes are unchanged now, so a hook installed and then removed still reads as equal, and a page the scan cannot read back, compare, or fit in its budget stays unverified rather than clean. Outside arm64, a process with neither AT_SYSINFO_EHDR nor a [vdso] mapping is taken as one the kernel gave no vDSO, so code that removes both goes unnoticed there.
- Result states: anomaly, review, clean; the [vdso] checks also report when the kernel mapped no vDSO.
- Interpretation: writable executable code, anonymous executable mappings outside ART, shared-dirty system code and a copied system page whose bytes differ from the file are danger; swapped executable pages and a copied system page that could not be compared are review; a copied system page equal to the file is clean. The app maps the WebView library into this process for its mount-view sampler, so this row sees both a tool that patches WebView in every process and the read-triggered copies above, and tells them apart by the copied page's bytes.

### Signal handlers

- Observable signal: the handlers installed for SIGTRAP, SIGBUS, SIGSEGV and SIGILL.
- Producing subsystem: the kernel's per-process signal actions.
- Mechanism: hooking and instrumentation frameworks install handlers that point into anonymous memory.
- References: Discovery only: the handler heuristics follow observed Frida and hook framework behaviour.
- Applicability: every ABI.
- Visibility limits: legitimate crash reporters install handlers too, which is why only suspicious targets count.
- Result states: detected, review, clean.
- Interpretation: handlers in anonymous or loader-suspicious memory are review or danger by target.

# Wrapped PTY reopen reference leak

## Question and producing subsystem

Does reopening an existing anonymous-inode PTY wrapper repeatedly leave approximately
one additional allocated kernel file object per successful reopen, while opening the
same terminal directly and idle periods do not show comparable growth?

This is a bounded diagnostic experiment, not a KernelSU identification mechanism.
It does not request root or create a privileged wrapper. Ordinary Android app processes
usually have no eligible descriptor; that result is **not evaluated**, never a negative
KernelSU verdict.

## Source basis and applicability

- [KernelSU #3958](https://github.com/tiann/KernelSU/pull/3958), merged on 2026-10-31,
  balances the successful reopen path. The PR reports a Pixel 11 Pro Fold with KSU 32709,
  768 wrapped reopens, direct-terminal controls, and a persistent counter increase.
  This is upstream reproduction evidence, not validation of this implementation.
- [Pre-fix file_wrapper.c](https://github.com/tiann/KernelSU/blob/51c217863c5e1fb639501e92ef17ac6d0cf90c92/kernel/infra/file_wrapper.c):
  `ksu_wrapper_open` calls `dentry_open`; `ksu_create_file_wrapper` takes another file
  reference; release drops only the wrapper-owned reference. Installation uses an
  anonymous inode, copies the original file mode and overrides dentry display with
  the original path. Reading a `/dev/pts/N` link alone cannot distinguish the wrapper.
- [Fix ae4b787d](https://github.com/tiann/KernelSU/commit/ae4b787d4bafc2884dd6a13a5a272a10ce13db24)
  drops the caller's reference after wrapper construction succeeds. Version numbers
  alone cannot establish whether a fork or backport contains this fix.
- [KernelSU dispatch](https://github.com/tiann/KernelSU/blob/51c217863c5e1fb639501e92ef17ac6d0cf90c92/kernel/supercall/dispatch.c)
  and [permission checks](https://github.com/tiann/KernelSU/blob/51c217863c5e1fb639501e92ef17ac6d0cf90c92/kernel/supercall/perm.c):
  GET_WRAPPER_FD requires manager/root authorization. An unprivileged scan cannot
  assume it can manufacture a wrapper for this experiment.
- Android Common Kernel `android15-6.6`, revision
  `3a8b5df06c041e54b2d9d6751f542858758eb29d`:
  [file_table.c](https://android.googlesource.com/kernel/common/+/3a8b5df06c041e54b2d9d6751f542858758eb29d/fs/file_table.c)
  exposes `file-nr` using `percpu_counter_read_positive`, counts file allocations,
  decrements on file release and can defer `fput` via task work or delayed work.
  It is an approximate system-wide allocation count, not this process's FD count
  and not an exact reference count.
  [proc/fd.c](https://android.googlesource.com/kernel/common/+/3a8b5df06c041e54b2d9d6751f542858758eb29d/fs/proc/fd.c)
  resolves a proc FD link to its file path;
  [anon_inodes.c](https://android.googlesource.com/kernel/common/+/3a8b5df06c041e54b2d9d6751f542858758eb29d/fs/anon_inodes.c)
  allocates pseudo files on the anonymous-inode mount.
  [tty_io.c](https://android.googlesource.com/kernel/common/+/3a8b5df06c041e54b2d9d6751f542858758eb29d/drivers/tty/tty_io.c)
  implements `TIOCGDEV` by returning the encoded device number of the underlying TTY;
  the wrapper forwards this ioctl to its original file.
  [fs sysctl documentation](https://android.googlesource.com/kernel/common/+/3a8b5df06c041e54b2d9d6751f542858758eb29d/Documentation/admin-guide/sysctl/fs.rst)
  defines the three counters and the zero unused-file field for modern kernels.
- [Android SELinux documentation](https://source.android.com/docs/security/features/selinux)
  explains mandatory access control and Android's restricted proc visibility.
  Namespace, OEM and policy differences may prevent candidate or counter access.
- [Bionic Android 16 fdsan.cpp](https://android.googlesource.com/platform/bionic/+/refs/heads/android16-release/libc/bionic/fdsan.cpp)
  implements `close` without retrying the syscall and converts EINTR to success.
  [ACK open.c](https://android.googlesource.com/kernel/common/+/3a8b5df06c041e54b2d9d6751f542858758eb29d/fs/open.c)
  clears the descriptor entry before final close status. The collector never retries
  a failed close against a potentially reused descriptor number.

The checked ACK branch establishes a mechanism, not universal device compatibility.
No instruction-set-specific operation is used. Candidate, direct-terminal and counter
capabilities are checked at runtime; unknown vendor accounting and other wrapper
implementations remain possible confounders. No Android/kernel/KSU version alone
produces either a positive or a negative result.

## Collection and ownership

The Native Root data module owns the POSIX collector and its JNI bridge. The domain
module classifies immutable observations; presentation owns wording and warning rows.
No flags identifying root or a root family are changed by this experiment.

Only the current process's FDs are enumerated. `F_DUPFD_CLOEXEC` pins a candidate
without running its `open` operation, avoiding FD-number reuse races. Eligibility
requires a character-device mode, anonymous-inode filesystem and numeric
`/dev/pts/N` displayed path. The direct path must open on devpts; both descriptors
must accept `isatty` and return matching `TIOCGDEV` device numbers. Every subsequent
open checks that device number again; each direct open must also retain the pinned
control's device/inode/rdev identity. A changed path or device stops the experiment.
TTY device numbers can be reused across distinct devpts mounts, so these checks do
not prove underlying mount identity. These checks describe a wrapper candidate, not proven KSU
provenance. All probe-owned FDs close on every exit. Original FDs are untouched.
Terminal opens use `O_NOCTTY | O_NONBLOCK | O_CLOEXEC`; no terminal data is read or
written. The direct path and wrapped path use the same access flags.

Each observation point is five `file-nr` reads spaced by 10 ms, recording median
and full range. Parse errors, nonzero unused counts, counter denial, incomplete
batches, deadline and close failures retain distinct collection states.

Excessive point spread or idle/direct drift stops collection immediately, before any
further wrapped reopens. The result stays inconclusive.

The sequence is baseline, then three rounds of:

1. Idle for 40 ms and sample.
2. Open/close the direct terminal 256 times, settle 40 ms and sample.
3. Reopen/close the pinned wrapper 256 times, settle 40 ms and sample.
4. Open/close the direct terminal 256 times, settle 40 ms and sample.

Finally settle 200 ms and sample again. This checks short-term persistence while the
process is still alive, not persistence after process exit. Delays reduce transient
release effects but cannot prove that every vendor's deferred release has completed.
An 8-second cooperative deadline is checked between operations. It cannot interrupt
a kernel call that does not return. Coroutine cancellation propagates after the bounded
native call; it never changes a failed experiment into a clean result.

There are at most 768 wrapped reopens and 1,536 direct control opens per collector
owner. The probe consumes admission before collection begins, caches its observation including
failures, and serializes concurrent calls. An exception or cancellation after entry
also consumes admission; an attempt that never returns an observation cannot be retried. Rescanning with that scanner reuses the same result. Creating a new scanner or
restarting the process creates a new budget; this is not a device-wide lifetime limit.
On affected kernels, closing descriptors cannot recover the leaked kernel references,
which can remain pinned after the process exits. Do not run repeated affected-kernel
experiments merely to obtain additional confidence.

## Interpretation and false-positive controls

A warning requires all of the following provisional gates:

- Complete successful collection and cleanup, all 768 reopens accounted for.
- Every observation's spread at most 64 objects.
- All idle/direct deltas and the final persistence delta within -64 through +64.
- Each reopen delta between 192 and 320 objects; their sum between 640 and 896.
- Baseline-to-final retained growth between 576 and 960 objects.

These are conservative engineering thresholds around the one-object-per-reopen
mechanism, not measured sensitivity/specificity bounds or a statistical confidence
level. They require cross-device calibration. System activity synchronized with the
stimulus can still imitate the pattern. CPU migration and approximate per-CPU
accounting can obscure or distort a genuine leak.

Quiet successful rounds with all reopen deltas within -64 through +64 report
**leak pattern not observed**. Other measured shapes are **inconclusive**. A single
spike, background growth during controls, excessive sampling noise, disappearing
growth, an incomplete run or any resource failure cannot produce a warning match.
A missing candidate is **not evaluated**. Fixed KSU, inaccessible wrappers, wrappers
outside this process and other file types are blind spots; none excludes KSU/root.

## Reproducible verification

Run the injected native sampler tests and Kotlin domain, protocol, lifecycle and
presentation tests:

```sh
python3 feature/nativeroot/data/src/test/native/test_ksu_wrapper_leak_probe.py
./gradlew :feature:nativeroot:domain:unitTest :feature:nativeroot:data:unitTest :feature:nativeroot:presentation:unitTest :app:assembleDebug
```

The native harness executes the production sampler and POSIX adapter with fake I/O
and never leaks real kernel resources. It verifies split/complete counter reads,
interrupted-read deadlines, terminal identity changes, denied ioctls and close failures.
It also checks native/Kotlin status codes against each other. It verifies ordering, successful-open accounting, parser
rejection, every sampler operation's failure path and cleanup. JVM tests exercise
noisy controls, incomplete samples, malformed JNI replies, caching and presentation.
Android compilation validates platform declarations and ABI portability.

Device validation should compare an unmodified environment, an eligible pre-fix
wrapper and the same setup with the reference fix. Record Android/API/security patch,
kernel build, ABI, KSU revision, permissions, namespace, every median/range and
background load. Include blocked procfs, failed direct opens and busy-system runs.
No attached Android device was available during implementation; on-device accuracy
and pre-fix/fixed differential behavior are not established by host tests.

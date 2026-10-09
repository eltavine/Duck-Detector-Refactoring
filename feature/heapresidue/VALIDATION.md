# Heap residue validation

The implementation is experimental. Source auditing and JVM fixtures do not validate the probe's
runtime transport, historical reach or robustness across OEMs. No device was connected during this
change (`adb devices -l` returned an empty list). Device results must be recorded before leaving Draft.

For issue #363's proposed process-name extensions, follow the separate
[experiment gates](research/nice-name/EXPERIMENTS.md) and
[source audit](research/nice-name/README.md). Binary scanner controls do not
establish renamed-manager coverage or authenticate a String's producer.

## Automated checks

Run the repository checks and the focused tests:

```sh
./gradlew :feature:heapresidue:domain:test :feature:heapresidue:presentation:test :feature:heapresidue:data:testDebugUnitTest
./gradlew unitTest checkPublicApi :app:assembleDebug buildHealth
python3 .github/scripts/check-evidence-records.py
python3 .github/scripts/check-detector-touch-points.py
python3 .github/scripts/check-reflection-boundaries.py
python3 .github/scripts/check-text-protocols.py
python3 .github/scripts/check-source-file-length.py
python3 .github/scripts/check-jni-contracts.py
python3 .github/scripts/check-native-boundaries.py
```

Fixtures cover both identifier widths, compressed and UTF-16 values, field linkage, arbitrary-array
and metadata rejection, package/process/path boundaries, duplicate correlation, every truncation of
a complete fixture, unknown heap tags, unsigned lengths, trailing bytes, dump-size budget, short
reads, random block boundaries with zero-length reads, at most budget + 1 source bytes consumed,
exclusion of the host's own arguments and malformed random inputs. Retention tests cover disabled mode, rolling
count, incomplete cleanup, storage failure and oversize pass-through. Domain/presentation tests
prove that a negative or failed scan never reads as all-clear and that findings do not claim current
installation or compromise.

## Device matrix and method

Record model, OEM/build fingerprint, API/security patch, ART module version, ABI, kernel/version,
USAP configuration and root/module environment for every run. Keep raw dumps local; report only
aggregate counts, policy-target matches and diagnostics.

1. On a stock API 36 device, test isolated service startup, hidden FD overload, reliable-pipe SELinux
   access, dump completion, local debug retention and repeated scans. Verify distinct child PIDs and
   child exit after completion/cancellation. Check UI responsiveness and wall-clock duration.
2. On a second Android version, verify explicit unsupported status and that no service or heap dump
   is started. Supporting that version requires a separate source/format audit and collection tests.
3. On a rooted/modified API 36 device, start known policy targets before collection. Repeat after
   uninstall/hiding a target and after reboot. Interpret strings as possible traces, not installation.
4. Instrument a test-only variant to collect at different offsets from process startup (immediate,
   0.5, 1, 2, 5, 10 and 30 seconds), record GC counters and correlate with collector logs. Do not
   assume every generation sweep removes non-moving objects. Do not ship delay instrumentation.
5. Launch several distinct apps between fresh captures. Check whether observed sets grow, shrink
   or differ; compare against a main-process snapshot and across ABI/zygote boundaries. Establish
   neither a boot-wide history nor monotonicity from one device.
6. Where controllable, compare USAP enabled/disabled and Java/native fork paths. Verify with
   device-side diagnostics that the collector's parent is the platform zygote, as source predicts
   for service launches, rather than inferring a fresh fork from bind.
7. Force binding denial, service death, hidden method failure, reader cancellation, dump over-budget,
   disk-full/permission failures and GC before capture. Verify unavailable/inconclusive results,
   bounded completion, descriptor cleanup, no lingering child or partial retained file, and that
   retention failure does not erase otherwise valid evidence. Make another process of the package
   fail to start while this binding is pending; verify one rebind with a new instance, and that a
   second death yields a binding-unavailable card rather than a stuck or cancelled scan.
   Record real dump sizes against the 256 MiB parse budget and the 32 MiB retention cap.
8. Compare debuggable and release hosts, including an SDK host with custom Application/providers.
   Release scans must create no raw files; debug files must stay in no-backup private storage and
   be limited to two/64 MiB. Verify merged manifest has isolatedProcess=true, exported=false and
   no app-zygote flag. Raw dumps must never enter an export/share/upload path.

## Open research

Zygote cleanup frequency, actual child GC cutoff, generation-specific survival, startup-set
monotonicity, actual USAP/native-path coverage and vendor compatibility remain unmeasured. Socket
strings are excluded entirely because their provenance is separate. Modified zygotes can erase or
forge strings. Performance measurements of synthetic fixtures do not measure ART stop-the-world
time, Binder throughput, filesystem cost or the real observation window.

## Recorded local results (2026-10-09)

Baseline: main `6125c427`. Host: Darwin arm64, Temurin OpenJDK 21.0.12.

- Focused tests: 24 passed (18 data/parser/retention, 3 domain, 3 presentation).
- `./gradlew unitTest checkPublicApi :app:assembleDebug buildHealth :sdk:aar:publish :sdk:aar:verifySdkAar :app:lintDebug`: passed. Debug and SDK native artifacts built for arm64-v8a, armeabi-v7a, x86 and x86_64. Lint had no unbaselined errors and no incidents in this feature; existing repository warnings remain.
- `./gradlew :build-logic:test`: passed.
- `./gradlew -p samples/sdk-consumer assembleDebug`: passed using the published fused AAR.
- All seven `.github/scripts/check-*.py` guards: passed.
- `python3 capability/selinuxpolicy/data/src/test/python/test_sidtab_native.py`: two baseline native tests passed.
- `git diff --check`: passed.

The synthetic parser test uses a 16,777,528-byte in-memory fixture dominated by one large irrelevant
byte array, three warmups and nine measured scans. The recorded median was 0.683 ms;
a separate 64 KiB buffered scan required 258 underlying reads. This tests block skipping and
bounded parser work for that fixture, not realistic object-heavy heap throughput, Android ART
stop-the-world time, Binder transport, disk cost or end-to-end scan performance. There is no
wall-clock performance threshold in CI.

Follow-up review (2026-10-09, same host): the parser now owns its block buffer instead of reading
byte by byte through a synchronized BufferedInputStream. A 16,814,327-byte object-heavy fixture in
ART-shaped 128-object segments (VM-internal root, 16-byte instance and int array per object) went
from a 27.1 ms to a 5.2 ms median; the large-array fixture went from 0.97 ms to 0.34 ms. Both read
the source in 258 blocks. Medians use five warmups and nine scans; they are host JVM figures only.
Focused tests: 28 passed (15 parser, 2 benchmark, 5 retention, 3 domain, 3 presentation).

Runtime device results remain unrecorded: `adb devices -l` was empty. In particular, pipe access,
hidden method invocation, eventual child exit after timeout, observation window and historic
coverage must not be considered validated by these host tests.

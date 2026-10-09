# Issue #363: device experiment gates

Status: planned, not executed. No connected device was available on 2026-10-09.
Source conclusions and current scanner controls are in [README.md](README.md).
Skipped experiments do not produce negative detector results.

## Questions and gates

1. **Collection:** does a fresh isolated scan observe verified non-host launch
   names? Its own arguments and synthetic Strings are insufficient. Transport
   failure or absent controls remain unavailable/inconclusive.
2. **Visibility:** which requests reached the platform zygote's Java path, its
   native loop, a USAP or an AppZygote, and which could reach the inherited heap?
   Test the source expectations: AppZygote startup always takes the Java path,
   boot-broadcast receiver launches may use a USAP, service launches may not.
   Establish routing through controlled samples and lab instrumentation; `_zygote`
   alone cannot certify ancestry.
3. **Rename:** does a candidate recover names missed by exact-package matching?
   Inspect the installed manifest and independently known launch path first.
4. **Collision:** does a benign app with the same suffix yield the same candidate?
   Indistinguishable content permits only weak unauthenticated name evidence,
   never root-state or unique-family attribution.
5. **Cost:** can matching use the existing dump and stream limits? Measure work
   and extra peak memory before adding an enabled rule.

Do not treat a failed earlier gate as passed. Missing/unsupported routes are
reported strata, not silently excluded from coverage statistics.

## Controlled samples

Use dedicated disposable lab devices. ADB may inspect/install benign fixtures;
it must not become a detector dependency. Neither the detector nor an automated
research harness invokes `su`, triggers a jailbreak, changes SELinux or grants
privileged permissions.

Prepare a benign fixture with explicit build variants:

| Variant | Deliberate behavior | Purpose |
| --- | --- | --- |
| Default | Main process and `:remote` / `:service` components | Non-host visibility baseline |
| Collision | Enabled `directBootAware` boot receiver in `:magica_boot`, no root code | Exact-suffix collision; boot-route survival |
| Global name | Component whose `android:process` equals a policy package | Collision with the existing NICE_NAME argument |
| ID-only rename | Different applicationId, retained namespace/classes/suffix | Separate package and component names |
| Component rename | Different namespace/classes; inspect final manifest | Class-token dependence |
| Suffix rename | Replace `:magica_boot` | Naming-only bypass |
| Isolated | Benign isolated service without AppZygote | Platform-zygote service-name control |
| AppZygote | Benign isolated service with harmless preload | `<fixture>_zygote` visibility versus child name |
| Instance binding | Two explicit isolated-binding instance names | Class/instance boundaries |
| Synthetic String | Exact argument allocated without that launch | Origin ambiguity |

This PR does not include or claim a built fixture APK. Record its source commit,
AGP/build variant, APK SHA-256, installed manifest and component state. Source XML
and applicationId alone do not establish the final component name.

Root-manager comparisons use preconfigured, explicitly controlled samples and
passive observation. Do not silently enable the disabled boot receiver or treat
direct MagicaService startup as harmless: its audited AppZygote preload invokes
native functionality. Never send `me.weishu.kernelsu.magica.LAUNCH` or
`me.bmax.apatch.magica.LAUNCH`; APatch's receiver is exported, so any sender can
start its jailbreak chain once it is enabled and root is unavailable. Record which path was already
activated and why. Mark unsafe or unavailable comparisons pending.

A `KSU_PACKAGE_NAME` manager is crowned only by a kernel or module built with the
same name. Record whether each renamed sample is functional or merely installed;
an installed-only sample still exercises naming, not a realistic deployment.

| Upstream sample | Required comparison | Expectation to test |
| --- | --- | --- |
| KernelSU pinned build | Default / `KSU_PACKAGE_NAME`; boot option off/on where safely preconfigured | Conditional boot suffix; direct service need not launch receiver |
| APatch pinned build | Default / explicit applicationId-only variant | Receiver disabled by default; activation must be evidenced |
| Both managers | Component and process-suffix changes | No arbitrary-repackaging guarantee |
| Magisk pinned build | Default / actual upstream hidden stub | Randomized package/components; no established stable token |
| Benign fixture | Identical suffix/name on stock device | No root or unique-family inference |

## Capture protocol

Keep API 36 and existing retention/resource limits. Runtime collection must not
obtain root, ADB, Shizuku, privileged Binder or another app's private data.

Predeclare at least 10 fresh scans per supported sample/timing/route cell as a
pilot, not proof of general correctness. Record every attempt including errors;
do not retry only until a positive result appears.

1. Record OEM/build fingerprint, API/security patch, ABI, kernel, ART/APEX version,
   USAP configuration and host/target build hashes. For controlled managers,
   additionally record root environment, component state and rename method.
2. Capture pre-launch baseline; launch the known benign component between host
   startup and a fresh isolated capture. Distinguish host/self arguments. Label
   prior-history contamination or reboot between experiments; do not assume GC
   or restart clears every relevant residue.
3. Collect at immediate, 0.5, 1, 2, 5, 10 and 30 second offsets from the
   collector's own start using a test-only collector. Record actual process age,
   dump duration and pre-call GC count. These are not an exact fork-to-freeze
   interval or proof of object survival. Do not ship delay instrumentation as
   detection logic.
4. Separately vary the interval between the known launch and the capture:
   seconds, minutes, and for boot routes the time since boot. Zygote-side
   survival over this interval, not the collector's own GC window, decides
   whether an early launch can still be observed.
5. Compare supported 32/64-bit zygotes, USAP configurations the lab can control,
   and platform/AppZygote routes. Mark unavailable routing diagnostics explicitly.
6. Compare across GC diagnostics and fresh scans. Do not require monotonic
   history or assume a child's later requests propagate back into its parent.
7. Compare original and candidate classification on the same bounded stream or
   local retained dump. Measure bytes, candidate count, distinct rule IDs, CPU/
   wall time and extra peak memory. No second runtime dump or repeated whole-heap
   scan per rule; no upload/export or benign-name inventory in reports.

Future classifier tests must cover malformed/overlength names, exact boundaries,
metadata/detached arrays, fully valid spoofs, mixed requests, truncation and
unsupported layout. Parse failures, limits and deadlines remain explicit failures.

## Result record and promotion decision

For every cell record sample hash/transformation, device/route, attempts and
complete/inconclusive/unavailable counts, observed rule IDs, independently known
launch path, age/GC diagnostics, cost ranges and limitations. Publish only matched
rule/family summaries and aggregate diagnostics, not benign names, UIDs, full
arguments or raw dumps. Retain heaps locally within the existing debug limits.

| Gate | Executed result | Decision |
| --- | --- | --- |
| Non-host visibility / transport | Not run | Pending |
| Routing / ABI / USAP / GC | Not run; source expectations recorded in README | Pending |
| Launch-to-capture survival, including since boot | Not run | Pending |
| Renamed-manager incremental coverage | Not run | Pending |
| `<policy package>_zygote` exact-name extension | Not run | Pending |
| Benign suffix or global-name collision | No device run; producible by any app per source | No authenticated root inference |
| Real-heap performance | Not run | No cost claim |

Promote only a precisely scoped weak name rule with demonstrated incremental
coverage, explicit collision semantics, bounded implementation and measured
cost. A shared suffix cannot uniquely identify KernelSU or APatch. If it cannot
be observed reliably or adds no useful coverage, document that negative result
and retire it. #363 remains open pending device evidence; a production alarm is
not required merely to complete this study.

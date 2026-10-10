# SELinux evidence record

Status: reviewed

The SELinux detector asks whether SELinux is enforcing for this app, whether the loaded policy grants rules stock policy denies, and whether audit output looks rewritten. An enforcing, clean result means these checks saw nothing wrong, not that the policy is stock.

## Signals

### Enforcement status

- Observable signal: /sys/fs/selinux/enforce, getenforce, the selinuxfs mount and this process's context in /proc/self/attr/current.
- Producing subsystem: the kernel's SELinux LSM and selinuxfs.
- Mechanism: selinuxfs exposes the enforce node to all readers; a denied read while the domain is enforcing, or a labelled context, bound what the mode can be.
- References: kernel/common security/selinux/selinuxfs.c (enforce node mode) and security/selinux/avc.c (avc_denied only denies when enforcing); system/sepolicy private/domain.te (every domain may search selinuxfs and getattr its files); Android CDD 9.7 (global enforcing mode is required).
- Applicability: every supported release.
- Visibility limits: some devices deny reading enforce; a denied read proves enforcing only through the paradox rule, and a labelled context proves SELinux is enabled, not enforcing.
- Result states: enforcing, enforcing (paradox), permissive, disabled, not observable, unknown.
- Interpretation: permissive or disabled are compatibility departures reported as danger; an unresolved mode stays unknown rather than defaulting to enforcing.

### Dirty policy rules

- Observable signal: whether the loaded policy allows edges stock policy denies, such as untrusted_app to magisk binder call or system_server execmem.
- Producing subsystem: the loaded SELinux policy, queried through an app_zygote access oracle.
- Mechanism: the capability asks security_compute_av style questions from app_zygote, with a control edge stock policy allows and one it denies to prove the oracle answers.
- References: system/sepolicy private/app_neverallows.te and the domain .te files for the stock expectations; capability/selinuxpolicy/EVIDENCE.md for the oracle.
- Applicability: Android releases whose app_zygote can reach the oracle; see the capability record.
- Visibility limits: an oracle that fails its own controls is untrusted; its answers are shown at lower confidence.
- Result states: rule present, not observed, untrusted oracle, unavailable.
- Interpretation: a trusted oracle's allowed edge is danger or a policy observation, as each rule's text says; untrusted answers never exceed warning.

### Context validity

- Observable signal: whether root-tool contexts are valid in the loaded policy, and the native and Java app_zygote tracks that carry the checks.
- Producing subsystem: the loaded SELinux policy, queried by the selinuxpolicy capability's carriers.
- Mechanism: a context is valid only if the loaded policy defines it, so a root-tool domain's validity shows the policy was extended.
- References: kernel/common security/selinux/selinuxfs.c (sel_write_context); capability/selinuxpolicy/EVIDENCE.md.
- Applicability: where a carrier can start.
- Visibility limits: a carrier that cannot start leaves the check unavailable.
- Result states: clean, valid root context, unavailable.
- Interpretation: a valid root-tool context is supporting evidence of a modified policy.

### Policy reload and status page

- Observable signal: the app_zygote seqno oracle: the status page's policyload counter against the access oracle's sequence number, and whether reading the status page killed the disposable child that read it.
- Producing subsystem: selinuxfs's status and access nodes, read through the selinuxpolicy capability's app_zygote carrier.
- Mechanism: a policy reload after boot, as root tools do to inject rules, leaves the two counters apart; a hook on the status node's open handler breaks its mapping, and the read kills the reader.
- References: kernel/common security/selinux/selinuxfs.c (status and access nodes); capability/selinuxpolicy/EVIDENCE.md (Policy reload and process context, Status page mapping).
- Applicability: where the app_zygote carrier starts; the oracle needs android:zygotePreloadName.
- Visibility limits: an odd sequence was read mid-update; a status page that was not read leaves the oracle unavailable.
- Result states: clean, seqno split, status page faulted, info, unavailable.
- Interpretation: a seqno split and a faulted status page are danger: the first shows a policy reload after boot, the second a status node whose kernel handler was altered. Info and unavailable leave the verdict to the other checks.

### Audit integrity

- Observable signal: whether a controlled AVC denial appears in app-readable auditd logs, whether allow or rewrite markers appear, and auditpatch module residue.
- Producing subsystem: logd's audit buffer and libselinux's callback in this process.
- Mechanism: a module that rewrites logd's audit output leaves the controlled denial missing, altered or tagged.
- References: system/sepolicy private/file_contexts (/data/adb is adb_data_file, not searchable by apps). Discovery only for the ZN-AuditPatch residue paths and log markers.
- Applicability: devices where the app can read its own audit events.
- Visibility limits: AOSP does not guarantee that apps see matching audit events; residue under /data/adb is not observable from apps.
- Result states: clear, residue, exposed, tampered, inconclusive; residue rows can be not observable.
- Interpretation: tampering is warning or danger; absence of residue or events is inconclusive.

### Policy analysis

- Observable signal: the policy version, dangerous types and permissive domains visible through selinuxfs.
- Producing subsystem: the loaded policy's exported metadata.
- Mechanism: a policy version below the release's minimum, root-tool types or permissive domains indicate a modified or debug policy.
- References: kernel/common security/selinux/selinuxfs.c for the exported nodes. Discovery only for the list of root-tool types.
- Applicability: readable only where selinuxfs grants the app those nodes.
- Visibility limits: unreadable nodes leave the analysis partial.
- Result states: strong, minor drift, review, weak, unreadable.
- Interpretation: permissive domains and dangerous types are warning or danger; unreadable fields are support.

### SID-table query consistency

- Observable signal: the selinuxpolicy capability's paired context-query/attr-current SID-table counter observations, repeated twice with four distinct canonical stock contexts per round.
- Producing subsystem: SELinux context registration in the current policy, compared across selinuxfs/context and the process attribute handler; see the capability's SID-table registration experiment.
- Mechanism: a query that only inserts into a backup SID table can accept a context without increasing live entries; a later attr/current write passed to the original handler can insert that same context into the live table even when its transition is denied. Both rounds must show context delta 0, attr delta 4, repeat delta 0, unchanged control/idle counts, an accepted carrier label, malformed context and attr/current controls rejected with EINVAL, successful canonical queries, issued attr writes rejected with EACCES, unchanged child identity and eight distinct candidates. The attr/current control is what places those EACCES rejections after context conversion; EPERM is not accepted because `proc_pid_attr_write` can return it before the SELinux hook runs. The alternate complete pattern (context delta 4, attr delta 0, repeat delta 0) is only "no discrepancy observed". Every other pattern is inconclusive.
- References: ACK [selinuxfs.c](https://android.googlesource.com/kernel/common/+/783025351c5fb3bcb4591d8fc61cbbd709aa4bcf/security/selinux/selinuxfs.c) (`sel_write_context`) and [hooks.c](https://android.googlesource.com/kernel/common/+/783025351c5fb3bcb4591d8fc61cbbd709aa4bcf/security/selinux/hooks.c) (`selinux_setprocattr`); the other pinned ACK/AOSP references in capability/selinuxpolicy/EVIDENCE.md; [KernelSU a810677b847ba564c5f9d3fa0fbabe54794b8eef](https://github.com/tiann/KernelSU/commit/a810677b847ba564c5f9d3fa0fbabe54794b8eef) and its parent `24d9bc3`, `kernel/feature/selinux_hide.c` (`my_write_context`, `my_write_access`, `my_setprocattr`). The parent routes app UID queries to a backup policy without global registration; the fix adds global conversions. This implementation measures context/attr paths, not the access path.
- Applicability: gated by the capability's carrier, interface and canonical context checks. The counter pattern is intended to expose unsynchronized query/registration implementations; KernelSU with hiding disabled or with this synchronization fix can behave like stock. KernelSU's SELinux hiding is opt-in: `ksu_selinux_hide_enabled` defaults to false, and enabling it fails with "please save feature and reboot" until a backup policy was captured at boot, which is dropped again when hiding stays off. The unsynchronized hooks (`my_write_context` answering app UIDs from the backup policy, `my_setprocattr` passing stock-valid labels to the original handler) ship in releases [v3.2.5](https://github.com/tiann/KernelSU/blob/b0bc817b4e966aa6aa830834eaf6ef765d821d40/kernel/feature/selinux_hide.c) and [v3.3.0](https://github.com/tiann/KernelSU/blob/932014ab5b2c9b74a3d11e2ec4d17dd10fc9442e/kernel/feature/selinux_hide.c); neither contains a810677. Among forks, KernelSU-Next carries the synchronization in [e01796b9](https://github.com/KernelSU-Next/KernelSU-Next/commit/e01796b94097e6bef8dffadcaacd78cfff1c18c6), while SukiSU-Ultra's file was last changed in [cf785ef9](https://github.com/SukiSU-Ultra/SukiSU-Ultra/blob/cf785ef9d681ac400848599c2f59e49f677bfd07/kernel/feature/selinux_hide.c) without it. These are source observations at the cited revisions; KernelSU forks/releases are not classified by version strings.
- Visibility limits: total entries are global, random candidates are not proven fresh, and a hidden reload or other processes can imitate/mask a paired pattern. Controls reduce ambiguity but cannot make these observations independent or authoritative. Control failures, missing/older payloads, permissions and incomplete measurements are not negative results.
- Result states: repeated discrepancy observed, no discrepancy observed, not collected, unsupported, permission limited, unavailable, inconclusive.
- Interpretation: repeated discrepancy is warning-level supporting evidence only, never KernelSU identification, root proof or a danger verdict. It ranks below the danger findings, a trusted dirty-policy rule hit and an untrusted carrier, and above the reduced-coverage carrier state, so that info-level state cannot hide it. Only a discrepancy adds a summary sentence and an impact item; no discrepancy observed and all failure/coverage states stay in informational method rows. This shares SELinux mechanisms with the context/access/seqno observations and is not counted as another independent root indicator.

Initial validation is source review plus JVM and injected native regression tests. Real
stock/pre-fix/fixed-kernel device measurements have not been obtained. The row and export
state the global-statistics limitation and the retained preload capture time; no sensitivity,
false-positive rate or coverage of all Android kernels is claimed.

### Experimental App Zygote AVC lookup profile

- Observable signal: the selinuxpolicy capability's per-batch AVC lookup deltas for payloads A and B (four rounds of 4096 rejected attr/current writes each, on one pinned CPU), its collection state and the paired timing medians.
- Producing subsystem: the SELinux attr/current handler and the AVC's per-CPU statistics, measured in a disposable child of the app_zygote preload; see the capability's App Zygote AVC lookup counters record.
- Mechanism: only a collected snapshot is classified. A payload costs one lookup per write when every batch lies in [1, 1.1] x 4096 lookups and two when every batch lies in [2, 2.1] x 4096; anything else, including rounds that disagree, is unclassified. Extra activity on the CPU and the counter reads only add lookups, so the bands allow a tenth above each count and nothing below it. A≈1/B≈1 is the stock handler's count; A≈1/B≈2 and A≈2/B≈2 mean an extra AVC query on the write path. Timing is shown but never classified, because the stock handler already treats the payloads differently.
- References: capability/selinuxpolicy/EVIDENCE.md (App Zygote AVC lookup counters) for the pinned ACK, AOSP and KernelSU sources and the source-derived lookup table; ACK [hooks.c](https://android.googlesource.com/kernel/common/+/783025351c5fb3bcb4591d8fc61cbbd709aa4bcf/security/selinux/hooks.c) (`selinux_setprocattr`) and [avc.c](https://android.googlesource.com/kernel/common/+/783025351c5fb3bcb4591d8fc61cbbd709aa4bcf/security/selinux/avc.c) (`avc_lookup`).
- Applicability: wherever the capability collected counters; see its record. The AVC carrier gate permits app_zygote MLS category suffixes, while full-label identity changes still invalidate collection. The KernelSU shapes in its table come from source review at the cited revisions, not from device measurements, and forks or later revisions can differ.
- Visibility limits: the counter is shared by every task on the CPU and does not show which code made a query, so a profile cannot attribute the extra lookup to KernelSU or to any tool. A≈1/B≈1 cannot exclude hooks that query only after their own parse fails, which includes KernelSU from df03912 with hiding enabled. Missing counters, permission limits and failed collection are coverage gaps, not negative results.
- Result states: A≈1/B≈1, A≈1/B≈2, A≈2/B≈2, unclassified (typed as `SelinuxAvcLookupProfile`); not collected, timing only, permission limited, unsupported, unavailable, inconclusive (`SelinuxAvcLookupCollection`).
- Interpretation: informational only. A≈1/B≈2 and A≈2/B≈2 add one informational impact line; every reading stays an informational method row and never changes the card's status, verdict or summary, and A≈1/B≈1 is shown as not clean. This shares the attr/current path with the controlled context-write and timing observations and is not counted as an independent root indicator.

### Controlled attr/current recognition and ordinary-app timing

- Observable signal: repeated candidate-context refusal classes with preceding/following malformed and stock controls in the app_zygote child, plus the existing ordinary-app paired timing samples.
- Producing subsystem: procfs and SELinux context conversion/permission checks; the capability owns controlled writes, while this feature owns ordinary-app timing and evidence interpretation.
- Mechanism: only a complete controlled result with two issued EACCES refusals classifies a candidate as recognized. Repeated EINVAL only says the tested label was not recognized through this path. Timing compares A (the running context) and B (equal length with leading newline), requiring matching EACCES refusals; a payload-sensitive difference may reflect extra processing, scheduling, auditing or a hook. A timing threshold is not an architectural guarantee.
- References: Android Common Kernel [hooks.c](https://android.googlesource.com/kernel/common/+/783025351c5fb3bcb4591d8fc61cbbd709aa4bcf/security/selinux/hooks.c) (`selinux_setprocattr`); capability/selinuxpolicy/EVIDENCE.md for additional ACK/AOSP controls and version-matched source; KernelSU [df03912](https://github.com/tiann/KernelSU/commit/df03912f70d92ff2aa9762ef82d607033d37e1da), [parent ab23091](https://github.com/tiann/KernelSU/blob/ab23091edfeddc774e1e880b0919b211808a193e/kernel/feature/selinux_hide.c), [3f388ef](https://github.com/tiann/KernelSU/commit/3f388ef137c78e1ca0c92c0ada3b8717cdcc4302) and [a810677](https://github.com/tiann/KernelSU/commit/a810677b847ba564c5f9d3fa0fbabe54794b8eef).
- Applicability: determined by source mechanisms and runtime controls, not package or KernelSU version strings. SELinux hiding is optional; a hidden backup policy can suppress recognized live types. Source-derived coverage is separated below; it has not been established by paired device measurements.
- Visibility limits: a failed carrier, SETCURRENT denial, open error or missing control cannot become a positive or negative integrity finding. Legacy uncontrolled records are informational. A stable timing difference does not prove a hook or identify KernelSU; earlier hook implementations can have no A/B difference. Shared SELinux mechanisms are not independent root indicators.
- Result states: context recognized, tested contexts not recognized, permission limited, unsupported, unavailable, inconclusive (typed as `SelinuxProcAttrCurrentVerdict`); experimental timing candidate, no reproducible asymmetry, unavailable.
- Interpretation: both positive signals are warnings in the overall card, method row and impact text. Existing stronger findings retain precedence. No negative observation implies absence of KernelSU or policy modifications: "tested contexts not recognized" and every failed collection state add one informational impact line that says so, and the raw per-write record stays in the method row.

| KernelSU source interval / configuration | Source-derived expectation for retained probes |
| --- | --- |
| Hiding disabled | Live root contexts may be recognized by existing context queries and controlled writes. A valid context still does not identify the installed tool. |
| Hiding enabled, before `3f388ef` adds the attr hook | Original attr/current conversion can expose live-valid candidates while selinuxfs queries answer against the backup. Controlled writes can support recognition. |
| `3f388ef` through the parent of `a810677` | Backup validation hides added root contexts. The existing two-round SID-table registration experiment targets the unsynchronized context-query/attr registration discrepancy. |
| `a810677` through `ab23091`, hiding enabled | Synchronization removes that SID-table signature and backup validation hides added contexts. Ordinary-app SETCURRENT denial occurs before payload parsing. No reliable coverage is claimed for this gap. |
| `df03912`, hiding enabled | A stock-valid A reaches backup parsing before original SETCURRENT refusal; leading-newline B skips parsing. Existing timing can seek this difference, but source ordering does not establish a measurable or unique signature. |

The intervals describe the cited source paths, not all releases, forks, backports or future changes.
Other root probes in the repository retain their own contracts; package visibility, seccomp-blocked
supercalls and manager inotify behavior do not close this coverage gap. Draft validation must
record Android/API, kernel revision/configuration, ABI, enforcing state, hiding setting, raw control
and candidate errors, child outcome and preload capture age on each stock/modified device.

## Known gaps

- The policy notes pick their severity by matching the note text; see docs/architecture/follow-ups.md.

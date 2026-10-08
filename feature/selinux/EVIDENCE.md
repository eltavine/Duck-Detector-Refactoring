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
- Mechanism: a query that only inserts into a backup SID table can accept a context without increasing live entries; a later attr/current write passed to the original handler can insert that same context into the live table even when its transition is denied. Both rounds must show context delta 0, attr delta 4, repeat delta 0, unchanged control/idle counts, successful canonical queries, rejected issued attr writes, unchanged child identity and eight distinct candidates. The alternate complete pattern (context delta 4, attr delta 0, repeat delta 0) is only "no discrepancy observed". Every other pattern is inconclusive.
- References: ACK [selinuxfs.c](https://android.googlesource.com/kernel/common/+/783025351c5fb3bcb4591d8fc61cbbd709aa4bcf/security/selinux/selinuxfs.c) (`sel_write_context`) and [hooks.c](https://android.googlesource.com/kernel/common/+/783025351c5fb3bcb4591d8fc61cbbd709aa4bcf/security/selinux/hooks.c) (`selinux_setprocattr`); the other pinned ACK/AOSP references in capability/selinuxpolicy/EVIDENCE.md; [KernelSU a810677b847ba564c5f9d3fa0fbabe54794b8eef](https://github.com/tiann/KernelSU/commit/a810677b847ba564c5f9d3fa0fbabe54794b8eef) and its parent `24d9bc3`, `kernel/feature/selinux_hide.c` (`my_write_context`, `my_write_access`, `my_setprocattr`). The parent routes app UID queries to a backup policy without global registration; the fix adds global conversions. This implementation measures context/attr paths, not the access path.
- Applicability: gated by the capability's carrier, interface and canonical context checks. The counter pattern is intended to expose unsynchronized query/registration implementations; KernelSU with hiding disabled or with this synchronization fix can behave like stock. KernelSU forks/releases are not classified by version strings.
- Visibility limits: total entries are global, random candidates are not proven fresh, and a hidden reload or other processes can imitate/mask a paired pattern. Controls reduce ambiguity but cannot make these observations independent or authoritative. Control failures, missing/older payloads, permissions and incomplete measurements are not negative results.
- Result states: repeated discrepancy observed, no discrepancy observed, not collected, unsupported, permission limited, unavailable, inconclusive.
- Interpretation: repeated discrepancy is warning-level supporting evidence only, never KernelSU identification, root proof or a danger verdict. No discrepancy observed and all failure/coverage states have informational method rows. The existing stronger findings retain precedence. This shares SELinux mechanisms with the context/access/seqno observations and is not counted as another independent root indicator.

Initial validation is source review plus JVM and injected native regression tests. Real
stock/pre-fix/fixed-kernel device measurements have not been obtained. The row and export
state the global-statistics limitation and the retained preload capture time; no sensitivity,
false-positive rate or coverage of all Android kernels is claimed.

## Known gaps

- The policy notes pick their severity by matching the note text; see docs/architecture/follow-ups.md.

# AGENTS.md

## Pragmatic Interpretation

Exercise independent judgment, remain evidence-driven, and avoid rigid or dogmatic application of this document. These guidelines are intended to improve engineering quality, not to replace technical reasoning. If an agent determines that a rule, workflow, reference requirement, or architectural recommendation in this document is inappropriate, excessive, outdated, or counterproductive for the specific development task, it may adapt, reinterpret, or revise it as necessary. Such adjustments should preserve the document's underlying positive intent: correctness, technical rigor, maintainability, modularity, security, and sound engineering judgment. Prefer practical truth over formal compliance, and do not follow a rule mechanically when doing so would clearly produce a worse technical result.


## Purpose

DuckDetector is an Android environment integrity diagnostics project.

All implementation work must prioritize:

* correctness,
* modularity,
* low coupling,
* traceable technical reasoning,
* version-aware behavior,
* reproducibility,
* and conclusions proportional to the evidence collected.

Security-sensitive behavior must not be implemented from assumptions, memory, copied snippets, community folklore, or undocumented expectations.

Research must precede design, and design must precede implementation.

---

# 1. Architecture Principles

DuckDetector follows strict principles of:

* modularity,
* separation of concerns,
* explicit ownership,
* low coupling,
* narrow interfaces,
* replaceable implementations,
* isolated platform-specific code,
* and minimal shared mutable state.

Each feature should own its own implementation wherever practical.

A feature should not depend on internal implementation details of another feature unless that dependency is explicitly part of the architecture.

Prefer:

* feature-oriented modules,
* small and explicit interfaces,
* stable domain models,
* dependency inversion where appropriate,
* dedicated platform adapters,
* dedicated JNI bridges,
* isolated native probes,
* explicit unsupported states,
* testable components.

Avoid:

* global state,
* hidden coupling,
* cross-feature implementation leakage,
* duplicated platform logic,
* unrelated shared utility classes,
* broad abstractions with unclear ownership,
* implicit dependencies,
* monolithic detector implementations.

Shared infrastructure must exist because multiple features genuinely share the same abstraction, not merely because moving code into a common package appears convenient.

---

# 2. Research Before Design

Before implementing, modifying, or drafting a non-trivial detector or platform-dependent feature, identify the subsystem responsible for the observed behavior.

Do not begin from:

> "How can DuckDetector detect this?"

Begin from:

> "What subsystem produces this observable behavior, and what authoritative source establishes its semantics?"

The expected workflow is:

```text
Observed behavior
    ↓
Responsible subsystem
    ↓
Authoritative documentation
    ↓
Actual implementation
    ↓
Version and device applicability
    ↓
Detection model
    ↓
Architecture
    ↓
Implementation
```

A detector must not be designed around an observation whose origin is not sufficiently understood.

---

# 3. Mandatory Technical References

The exact references depend on the subsystem being modified.

There is no single reference hierarchy that applies equally to every detector.

The following sources are mandatory when applicable.

## 3.1 Android Platform Documentation

Consult official Android documentation first for public platform behavior.

Primary sources include:

* Android Developers documentation
* Android platform documentation on `source.android.com`
* Android security documentation
* Android compatibility documentation where relevant
* Android API references
* official Android architecture documentation

Documentation is not always sufficient by itself.

When implementation details affect detector semantics, verify them against the corresponding source code.

---

# 4. AOSP Source Code

For Android userspace and framework behavior, inspect the actual AOSP subsystem responsible for the behavior.

Relevant source trees may include:

```text
frameworks/base
system/core
system/security
system/sepolicy
bionic
art
packages/modules/*
hardware/interfaces
system/libhidl
external/*
```

This list is illustrative, not exhaustive.

Do not cite or reason from "AOSP" generically.

Locate the exact subsystem, class, native component, service, HAL interface, daemon, policy, or runtime code that defines, exposes, or enforces the behavior.

For example:

* process behavior may require inspecting Zygote and ActivityManager implementation,
* property behavior may require Bionic and init/property service code,
* runtime behavior may require ART,
* linker behavior may require Bionic linker code,
* permissions may require PackageManager and permission-controller implementation,
* SELinux behavior may require both AOSP policy and kernel behavior.

AOSP source must be matched to the Android version being analyzed whenever behavior may have changed between releases.

---

# 5. Android Kernel Sources

For kernel-dependent Android behavior, the primary kernel reference is **not generic upstream Linux by default**.

Prefer the Android kernel sources applicable to the Android environment being analyzed.

## 5.1 Android Common Kernel

For generic Android kernel behavior, inspect the applicable:

* Android Common Kernel,
* ACK branch,
* GKI branch,
* common kernel modules,
* Android kernel documentation.

The Android version and kernel version must be matched whenever possible.

Examples of relevant distinctions include:

```text
android-mainline
android14-5.15
android14-6.1
android15-6.6
other applicable ACK/GKI branches
```

Do not assume that behavior observed in one ACK branch applies unchanged to another.

## 5.2 Device and Vendor Kernel Sources

Where behavior depends on an actual device implementation, inspect the applicable:

* device kernel tree,
* vendor kernel tree,
* vendor kernel modules,
* Google-maintained device kernel sources,
* SoC-specific kernel components,
* device tree sources,
* kernel configuration,
* vendor drivers.

This is particularly important for:

* procfs behavior,
* sysfs interfaces,
* Binder extensions,
* TEE drivers,
* virtualization,
* boot state,
* vendor security modules,
* firmware interfaces,
* device-specific root indicators,
* hardware-backed security behavior.

Device-specific behavior must not be generalized into an Android-wide invariant without independent evidence.

---

# 6. Upstream Linux

Upstream Linux remains an important reference, but it is generally a **provenance and semantics source**, not automatically the source of truth for the kernel actually running on an Android device.

Consult upstream Linux when necessary to determine:

* original kernel semantics,
* upstream implementation behavior,
* provenance of Android kernel patches,
* backported behavior,
* subsystem design,
* historical implementation changes,
* behavior inherited by ACK.

When relevant, compare:

```text
upstream Linux
    ↓
Android Common Kernel
    ↓
device/vendor kernel
    ↓
observable behavior on Android
```

Never assume that mainline Linux behavior is identical to the Android kernel shipped by a device.

---

# 7. CPU Architecture References

Architecture-specific behavior must be verified against the official architecture specification.

## 7.1 Arm

For Arm and AArch64 behavior, consult the applicable official Arm references.

These may include:

* Arm Architecture Reference Manual
* system register documentation
* AAPCS / ABI documentation
* Generic Timer architecture
* exception model documentation
* memory model documentation
* virtualization architecture
* instruction semantics
* privilege-level behavior
* architectural feature documentation

If a probe uses an instruction or system register, determine:

* whether it is architecturally available,
* which exception levels may access it,
* whether access can trap,
* whether virtualization can alter behavior,
* whether implementation-defined behavior exists,
* and whether the assumption holds across supported Arm architecture versions.

Do not infer architectural guarantees from behavior observed on a single SoC.

## 7.2 x86 and x86_64

Architecture-specific x86 probes must use the applicable:

* Intel architecture manuals,
* AMD architecture manuals,
* ABI documentation,
* virtualization documentation,
* architectural CPUID or MSR documentation.

Do not assume Arm-specific reasoning applies to x86 or x86_64.

---

# 8. SoC, TEE, Firmware, and Vendor References

When behavior depends on SoC, firmware, TEE, boot-chain, secure-world, or vendor implementation details, inspect the applicable vendor material.

Relevant vendors may include:

* Qualcomm
* MediaTek
* Google
* Samsung
* Arm
* Intel
* AMD
* other applicable silicon or platform vendors

Relevant material may include:

* official documentation,
* open-source kernel code,
* firmware interface definitions,
* HAL definitions,
* TEE interface documentation,
* secure monitor interfaces,
* boot-chain documentation,
* technical reference manuals,
* vendor kernel modules.

Vendor-specific references are mandatory only when the feature actually depends on vendor-specific behavior.

Do not require unrelated vendor documentation for generic Android behavior.

---

# 9. Mandatory Reference Matrix

Use the following mapping as the minimum research expectation.

| Feature or subsystem            | Required references                                                                 |
| ------------------------------- | ----------------------------------------------------------------------------------- |
| Android public APIs             | Android Developers documentation                                                    |
| Android framework internals     | Android docs + relevant AOSP implementation                                         |
| Package visibility              | Android docs + PackageManager implementation                                        |
| Permissions                     | Android docs + permission framework implementation                                  |
| Zygote / process startup        | AOSP Zygote + related framework/native code                                         |
| ART / runtime                   | AOSP ART                                                                            |
| JNI behavior                    | JNI specification + relevant ART/native implementation                              |
| Bionic / libc                   | AOSP Bionic                                                                         |
| Dynamic linker                  | AOSP Bionic linker                                                                  |
| System properties               | AOSP Bionic + init/property service                                                 |
| Binder                          | AOSP Binder userspace + applicable Android kernel Binder driver                     |
| SELinux                         | Android SELinux docs + AOSP sepolicy + applicable kernel LSM/SELinux implementation |
| Mount namespaces                | AOSP process/init logic + applicable Android kernel                                 |
| `/proc`                         | applicable Android kernel + process visibility context                              |
| sysfs                           | applicable Android/device/vendor kernel                                             |
| GKI behavior                    | GKI docs + applicable ACK branch                                                    |
| Kernel detector                 | applicable ACK/GKI branch + device/vendor kernel when needed                        |
| Device-specific kernel behavior | device/vendor kernel and modules                                                    |
| KeyStore                        | Android security docs + AOSP Keystore                                               |
| KeyMint                         | Android docs + KeyMint HAL/AIDL definitions and implementation where relevant       |
| StrongBox                       | Android docs + applicable hardware/vendor implementation                            |
| Attestation                     | Android attestation docs + AOSP/KeyMint behavior                                    |
| TEE                             | Android interface + applicable SoC/TEE documentation                                |
| Virtualization                  | Android virtualization implementation + kernel + architecture specification         |
| Arm instruction probes          | Arm Architecture Reference Manual                                                   |
| Arm system-register probes      | Arm ARM + system-register documentation                                             |
| Arm timer probes                | Arm Generic Timer documentation                                                     |
| x86 architectural probes        | Intel/AMD architecture manuals                                                      |
| Qualcomm-specific behavior      | applicable Qualcomm documentation/source                                            |
| MediaTek-specific behavior      | applicable MediaTek documentation/source                                            |
| Google Tensor-specific behavior | applicable Google kernel/device/vendor source                                       |
| Samsung-specific behavior       | applicable Samsung/vendor source                                                    |

This table is a minimum, not a substitute for engineering judgment.

---

# 10. Version and Branch Matching

Android internals are highly version-sensitive.

Before relying on platform behavior, determine as precisely as practical:

* Android version,
* API level,
* AOSP release or tag,
* kernel version,
* ACK/GKI branch,
* device kernel revision,
* vendor module revision,
* CPU architecture,
* SoC family,
* OEM implementation,
* relevant security patch level.

Do not infer that behavior from one Android version applies unchanged to another.

Do not infer that behavior from one kernel branch applies unchanged to another.

Do not infer that behavior from one OEM or SoC applies to another.

Version differences should be explicitly represented in the implementation where they affect correctness.

---

# 11. Reference Quality

Prefer primary sources.

## Tier 1 — Authoritative Sources

Use these as the primary basis for detector semantics:

* Android official documentation
* AOSP source code
* Android Common Kernel / GKI source
* applicable device or vendor kernel source
* official architecture specifications
* official SoC/vendor documentation
* official interface specifications

## Tier 2 — Supporting Technical Sources

These may support or explain Tier 1 sources:

* upstream Linux
* upstream project source code
* standards documents
* academic papers
* security research papers
* conference presentations
* vendor technical papers

## Tier 3 — Discovery Sources

These may be used to discover behavior, bugs, bypasses, or implementation leads:

* GitHub issues
* mailing-list discussions
* blog posts
* Stack Overflow
* forums
* Reddit
* Telegram
* X
* other community discussions

Tier 3 sources must not be the sole technical basis for a security-sensitive detector when authoritative sources are available.

---

# 12. Detector Evidence Model

Every detector should be explainable through the following chain:

```text
observable signal
    ↓
producing subsystem
    ↓
implementation mechanism
    ↓
authoritative source or specification
    ↓
applicability constraints
    ↓
DuckDetector interpretation
```

If this chain cannot be established with reasonable confidence, the detector must not present the result as authoritative.

A finding must represent the strength of the evidence actually collected.

---

# 13. No Speculative Detection

Do not implement a detector merely because a heuristic appears to work on one test device.

Before accepting a signal, determine:

* what causes it,
* whether legitimate devices can also produce it,
* whether modified devices can hide it,
* whether Android sandboxing affects visibility,
* whether SELinux affects visibility,
* whether namespaces affect visibility,
* whether OEM modifications affect it,
* whether kernel configuration affects it,
* whether architecture affects it,
* whether permissions affect it,
* whether Android version affects it.

Possible result states should include, where appropriate:

* detected,
* not detected,
* unsupported,
* unavailable,
* permission-limited,
* inconclusive,
* partially evaluated,
* lower-confidence.

Absence of evidence must not automatically be interpreted as evidence of absence.

---

# 14. Evidence Correlation

Prefer multiple independent signals over one fragile heuristic.

Where practical, correlate evidence across:

* Kotlin/framework APIs,
* native code,
* direct syscalls,
* procfs,
* kernel-exposed state,
* Binder,
* isolated processes,
* mount namespaces,
* KeyStore,
* attestation,
* timing behavior,
* architecture-specific observations.

Signals derived from the same underlying mechanism should not be falsely represented as independent evidence.

---

# 15. Native Code

Native code must remain narrowly scoped.

JNI is an architectural boundary.

It must not become an unrestricted shared-state mechanism between Kotlin and native code.

Prefer:

```text
feature
    ↓
feature-specific JNI bridge
    ↓
narrow native implementation
```

Avoid:

```text
global JNI utility
    ↓
all native detectors
    ↓
shared mutable state
```

Native APIs should:

* use explicit data structures,
* expose narrow contracts,
* clearly represent failures,
* avoid unnecessary global state,
* document ABI-specific assumptions.

---

# 16. Architecture-Specific Code

Architecture-specific code must be isolated by ABI.

Supported ABIs may include:

```text
arm64-v8a
armeabi-v7a
x86
x86_64
```

Do not silently assume equivalent behavior between them.

An Arm-specific implementation must not be exposed as a generic Android invariant.

Architecture-specific probes should use compile-time or runtime dispatch where appropriate and must return an explicit unsupported state on unsupported architectures.

---

# 17. Vendor-Specific Code

Vendor-specific behavior must be isolated behind explicit abstractions.

For example:

```text
generic detector interface
    ├─ generic Android implementation
    ├─ Qualcomm-specific implementation
    ├─ MediaTek-specific implementation
    └─ Google-specific implementation
```

Do not scatter vendor checks throughout unrelated code.

Vendor identification itself must also be treated carefully and must not rely on one unverified property when stronger evidence is available.

---

# 18. Android Permissions and Visibility

Android application sandboxing fundamentally limits observable state.

Before interpreting a failed or empty probe, determine whether the result means:

```text
condition absent
```

or merely:

```text
condition not observable from this process
```

Consider:

* package visibility,
* SELinux,
* procfs restrictions,
* namespace isolation,
* permission restrictions,
* app UID boundaries,
* isolated processes,
* target SDK behavior,
* Android release changes.

Visibility limitations must be represented in detector semantics.

---

# 19. Security Conclusions

DuckDetector provides diagnostic evidence.

Do not convert heuristic evidence into claims such as:

* "the device is secure",
* "the device is compromised",
* "root is impossible",
* "the environment is trusted",
* "the TEE is genuine",

unless the underlying mechanism actually provides such a guarantee.

Prefer descriptions such as:

* evidence detected,
* evidence not observed,
* inconsistent state observed,
* probe unavailable,
* unsupported environment,
* confidence reduced,
* multiple indicators correlated.

Security conclusions must remain proportional to the evidence.

---

# 20. Design Before Coding

Before implementing a substantial feature:

1. Define the exact security or integrity question.
2. Identify the subsystem responsible for the relevant behavior.
3. Read the relevant Android documentation.
4. Inspect the relevant AOSP implementation.
5. Inspect the applicable Android kernel source if the feature crosses into kernel behavior.
6. Inspect device/vendor kernel code when behavior is device-specific.
7. Inspect architecture documentation when CPU behavior matters.
8. Inspect SoC/vendor documentation when implementation-specific behavior matters.
9. Determine Android/version/kernel applicability.
10. Identify false-positive conditions.
11. Identify false-negative conditions.
12. Identify visibility limitations.
13. Define unsupported states.
14. Define the evidence model.
15. Define module ownership and boundaries.
16. Define Kotlin/native boundaries if native code is required.
17. Only then implement the feature.

---

# 21. Code Comments and Technical Documentation

Comments should explain why a detector is technically valid.

Do not write comments that merely restate the code.

Useful comments may identify:

* the responsible Android subsystem,
* the relevant AOSP component,
* the applicable ACK/GKI behavior,
* the architecture rule involved,
* a vendor-specific dependency,
* an Android-version limitation,
* an OEM-specific exception,
* why a result is only heuristic,
* why a fallback exists.

Where practical, security-sensitive logic should retain enough context that another contributor can trace its assumptions back to authoritative material.

---

# 22. Failure Handling

Low-level probes must fail explicitly.

Do not silently map:

* syscall failure,
* permission denial,
* unavailable file,
* inaccessible service,
* unsupported architecture,
* missing hardware support,
* parser failure,
* service timeout,

to:

```text
not detected
```

These states have different meanings and must remain distinguishable when they affect interpretation.

---

# 23. Testing Expectations

Where practical, test:

* expected clean behavior,
* expected modified behavior,
* unsupported devices,
* unsupported architectures,
* permission-restricted behavior,
* malformed input,
* inaccessible system interfaces,
* version-specific branches,
* vendor-specific branches.

A detector validated only against one developer device is not sufficient evidence of general correctness.

---

# 24. Avoid Feature Leakage

Detector code should remain within the feature that owns it.

Do not introduce unrelated behavior into:

* global application classes,
* common UI packages,
* generic utilities,
* unrelated repositories,
* shared native initialization,

merely for convenience.

If multiple features require the same capability, extract a narrowly defined shared abstraction only after the common responsibility is clear.

---

# 25. Refactoring Rules

Refactoring must preserve detector semantics unless the change explicitly intends to alter them.

When moving security-sensitive logic:

* preserve behavioral assumptions,
* preserve failure-state distinctions,
* preserve version checks,
* preserve evidence confidence,
* preserve architecture-specific behavior,
* preserve process-boundary behavior.

A cleaner abstraction is not an improvement if it erases important platform distinctions.

---

# 26. Implementation Priority

When tradeoffs exist, use the following priority:

```text
Correctness
    ↓
Technical defensibility
    ↓
Evidence quality
    ↓
Architecture
    ↓
Maintainability
    ↓
Performance
    ↓
Implementation convenience
```

Performance may justify native or architecture-specific implementation, but it must not weaken correctness or evidence semantics.

---

# 27. Final Engineering Rule

The required sequence is:

```text
Research
    ↓
Verify
    ↓
Model
    ↓
Design
    ↓
Implement
    ↓
Test
    ↓
Document
```

For DuckDetector:

**Research first. Design second. Implement third.**

Every substantial detector should have a technically defensible path from:

```text
platform behavior
→ authoritative source
→ observable signal
→ implementation
→ interpretation
```

Modularity must be preserved, coupling must remain minimal, platform behavior must be verified against the correct Android version and implementation, and security conclusions must never exceed the evidence collected.

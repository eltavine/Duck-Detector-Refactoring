# Bootloader evidence record

Status: reviewed

The Bootloader detector asks whether the bootloader is locked and verified boot is intact, correlating hardware-attested state with the runtime's own properties. Attested state is the stronger evidence; properties can be spoofed.

## Signals

### Attested boot state

- Observable signal: RootOfTrust deviceLocked, verifiedBootState, verifiedBootKey and verifiedBootHash from a fresh attestation.
- Producing subsystem: the bootloader, which passes these values to KeyMint, and KeyMint's attestation.
- Mechanism: KeyMint signs the boot state it received from the bootloader into the attestation extension.
- References: hardware/interfaces security/keymint/aidl KeyCreationResult.aidl (RootOfTrust schema); capability/attestation/EVIDENCE.md.
- Applicability: devices with hardware-backed attestation; AOSP allows Verified with deviceLocked=false on approved test devices.
- Visibility limits: the attestation reaches this app through keystore2 and can be substituted by an interception module.
- Result states: locked and verified, unlocked, self-signed, unverified, failed, unavailable.
- Interpretation: an attested unlock or failed state is danger; a spoofable property alone is weaker.

### Boot consistency

- Observable signal: whether the attested verifiedBootHash matches ro.boot.vbmeta.digest, and whether the hash or key is all zeros.
- Producing subsystem: AVB in the bootloader, which computes the vbmeta digest, and init, which exposes it.
- Mechanism: on a genuine device both views carry the same vbmeta digest.
- References: [Android RootOfTrust fields and boot-state semantics](https://source.android.com/docs/security/features/keystore/attestation#rootoftrust_fields); hardware/interfaces KeyCreationResult.aidl; system/core init/property_service.cpp (androidboot.* to ro.boot.*).
- Applicability: comparison requires a Verified or SelfSigned attested state. Failed provides no guarantees about the other RootOfTrust fields; Unverified allows an all-zero verifiedBootKey and does not establish a chain of trust. Unknown states are not compared.
- Visibility limits: a missing RootOfTrust, missing attested hash, unreadable property or empty runtime digest leaves the comparison unperformed. A readable property alone cannot establish alignment. An empty readable digest with a usable attested hash in a comparable state retains the existing missing-digest anomaly.
- Result states: aligned, mismatch, missing, not compared.
- Interpretation: a contradiction between the two views is danger. Only a completed runtime comparison without a hard anomaly is Aligned / SAFE in findings and Aligned / CLEAN in the method summary. All other non-anomalous results are Not compared / INFO (SUPPORT in the method summary), matching the TEE report's use of runtimeComparisonPerformed. Existing mismatch, missing-digest and zero-value anomaly findings take precedence.
- Presentation: the card summary describes the absence of observed contradictions and directs readers to individual checks for coverage. It does not assert that attestation and properties were aligned when their digest comparison was unavailable.
- Validation: `./gradlew :feature:bootloader:data:unitTest :feature:bootloader:presentation:unitTest :capability:attestation:data:unitTest :feature:tee:data:unitTest`. Regression cases cover a readable property without a comparison, unavailable properties, completed comparisons and each hard anomaly. Probe-to-method cases cover missing roots and hashes, Unverified, Failed and unknown states, plus actual matched and mismatched digests. Probe tests also cover unavailable properties and SelfSigned. Presentation tests retain informational rows and avoid an unconditional alignment claim in the summary.

### VBMeta digest of empty input

- Observable signal: ro.boot.vbmeta.digest equal to the SHA-256 or SHA-512 digest of empty input.
- Producing subsystem: AVB in the bootloader, which passes androidboot.vbmeta.digest, and init, which checks it at first-stage mount and exposes it; or a tool that rewrote the property after boot.
- Mechanism: libavb sets androidboot.vbmeta.size and androidboot.vbmeta.digest from the same loaded vbmeta images, which always include the top-level one, so the digest always covers non-empty input; with verification disabled it adds no androidboot.* option at all. On a locked device whose fstab uses avb, first-stage init reloads the vbmeta images, recomputes their size and digest, and fails the mount when the bootloader's values are missing or differ. The digest of empty input therefore never comes from verified boot.
- References: external/avb libavb/avb_cmdline.c (avb_append_options) and libavb/avb_slot_verify.c (avb_slot_verify_data_calculate_vbmeta_digest; no androidboot.* options when verification is disabled); system/core fs_mgr/libfs_avb/fs_avb.cpp (AvbVerifier, AvbHandle::Open, IsAvbPermissive) and init/first_stage_mount.cpp (InitAvbHandle). Discovery only for the Specter module's boot_hash.sh, which writes ro.boot.vbmeta.* with resetprop from a shell sha256sum and caches the result, which is how the value reported in issue 157 was traced, and for the stock Galaxy S20 fstab.exynos990 quoted in Magisk issue 2559, which uses avb=vbmeta.
- Applicability: every device; the check reads only the property and needs no attestation.
- Visibility limits: a device whose bootloader does not use libavb and whose first-stage mount does not use fs_mgr AVB has no such guarantee; none is known. A tool that writes a plausible digest is not caught here and is left to the attestation comparison.
- Result states: empty-input digest, other value.
- Interpretation: an empty-input digest is danger: something other than verified boot wrote the property. Unlike the attestation comparison, it still fires when attestation is unavailable or reports the same value.

### Boot properties and raw boot parameters

- Observable signal: verified boot, lock, AVB and verity properties from several sources, and androidboot.* values in /proc/cmdline and /proc/bootconfig.
- Producing subsystem: init's property service and the bootloader's command line.
- Mechanism: a spoofing module that rewrites properties in one source often misses another.
- References: system/core init/property_service.cpp (ProcessKernelCmdline and ProcessBootconfig); bionic libc/include/sys/system_properties.h; capability/systemproperties/EVIDENCE.md.
- Applicability: /proc/bootconfig exists on Android 12 and later kernels.
- Visibility limits: /proc/cmdline and bootconfig are often unreadable for apps.
- Result states: danger, warning, consistent, unavailable.
- Interpretation: disagreement between sources is itself evidence of rewriting.

### Samsung warranty fuse and Widevine

- Observable signal: ro.boot.warranty_bit and ro.boot.knox.state on Samsung devices, and the Widevine security level and credential through MediaDrm.
- Producing subsystem: Samsung's bootloader, and the Widevine DRM plugin.
- Mechanism: Samsung trips a permanent fuse on unofficial boot images; Widevine L1 is withheld from unlocked devices on many vendors.
- References: Discovery only: the warranty properties and the Widevine behaviour are vendor behaviour, not documented AOSP contracts, and the meaning of the sentinel system ID is unconfirmed. vendor/widevine libwvdrmengine/cdm/core/src/crypto_session.cpp and oemcrypto_adapter_dynamic.cpp at android-9.0.0_r1 show the system ID read from the L1 keybox or OEM certificate, and the CDM falling back to L3 when that credential is invalid.
- Applicability: the warranty properties exist only on Samsung devices; Widevine behaviour varies by vendor.
- Visibility limits: Widevine can be unavailable for reasons unrelated to the bootloader; a wiped or invalid keybox can produce the same credential signs as an unlock.
- Result states: tripped, not tripped, conflict, consistent, unavailable.
- Interpretation: a tripped fuse is danger. A Widevine credential conflict, an L1 claim contradicted by the system ID or the maximum session, is shown as a review item and does not set the verdict on its own; a Java/NDK property mismatch points to an in-process MediaDrm hook and is a warning.

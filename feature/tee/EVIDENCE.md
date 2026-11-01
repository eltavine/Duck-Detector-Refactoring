# TEE evidence record

Status: reviewed

The TEE detector asks whether this device's hardware-backed keystore behaves like a genuine TEE or StrongBox KeyMint seen through an unmodified keystore2, and whether its attestation chain is consistent with that. It reports evidence; a clean result does not prove the TEE is genuine.

## Signals

### Attestation chain and RootOfTrust

- Observable signal: the attestation certificate chain of a freshly generated key and the fields of its attestation extension. The rows are Local chain, Trust root, Chain layout, Root fingerprint, RKP, RKP manufacturer, CRL, Tier, Challenge, Verified boot, Boot consistency, Versions (OS, vendor and boot patch levels), Device IDs, Key properties, User auth, Application and Module hash.
- Producing subsystem: KeyMint in the TEE or StrongBox, reached through keystore2, which also appends the RKP or factory certificates.
- Mechanism: the attestation extension carries a KeyDescription whose RootOfTrust holds deviceLocked, verifiedBootState and verifiedBootHash; the chain must verify up to a Google or known root and not appear in Google's revocation list.
- References: hardware/interfaces security/keymint/aidl KeyCreationResult.aidl (KeyDescription and RootOfTrust schema).
- Applicability: KeyMint devices on Android 12 and later, and Keymaster 4 devices behind keystore2's compatibility layer; StrongBox only where advertised.
- Visibility limits: the chain is whatever keystore2 returns to this app, so a process that intercepts keystore2 can substitute it; revocation is checked online only with the user's consent and otherwise against the bundled list.
- Result states: consistent, suspicious, tampered, broken (no hardware-backed trust), inconclusive.
- Interpretation: chain and policy contradictions raise hard or soft policy indicators; a consistent chain is reported as aligned, never as proof that the TEE is genuine.

### RKP provisioning build metadata

- Observable signal: CBOR key 5 in the provisioning information extension, OID `1.3.6.1.4.1.11129.2.1.30`, displayed in the RKP build metadata row with its original nested keys and values.
- Producing subsystem: the remote provisioning server that issues the attestation signing certificate; this is certificate-time server metadata, not a fresh CTS execution on the device.
- Mechanism: choose the provisioning extension nearest the root, require adjacency to the trusted attestation extension, a pinned Google root and valid local chain signatures, then decode the DER OCTET STRING and CBOR map. The OCTET STRING wrapper must match its DER re-encoding; non-minimal BER lengths and constructed wrappers are rejected. The decoder accepts nested maps, booleans, byte strings and future fields without discarding known fields. Invalid known field types are reported separately; malformed DER/CBOR, duplicate keys and trailing data are unavailable. The decoding limit is 64 KiB; diagnostic text beyond 8192 characters is explicitly truncated, and metadata exceeding 32 collection nesting levels is explicitly unavailable for display.
- References: [Android verification procedure](https://developer.android.com/privacy-and-security/security-key-attestation#retrieve-and-verify), [provisioning extension schema](https://source.android.com/docs/security/features/keystore/attestation#provisioninginfo_extension_schema), [X509Extension DER contract](https://developer.android.com/reference/java/security/cert/X509Extension#getExtensionValue(java.lang.String)), and [Android 16 RKP interface versioning](https://android.googlesource.com/platform/hardware/interfaces/+/android-16.0.0_r1/security/rkp/aidl/android/hardware/security/keymint/IRemotelyProvisionedComponent.aidl). Discovery only: [issue 566467877](https://issuetracker.google.com/issues/566467877) reports key 5 and APPROVED / NOT_APPROVED values; as checked on 2026-10-22, the issue is assigned and contains no authoritative definition of their nested schema or approval semantics.
- Applicability: any collected chain carrying this extension. Its map is unversioned and key 5 is optional and undocumented. RKP V3 is a provisioning protocol generation (introduced with Android 14), distinct from the attestation extension version and KeyMint version; neither Android release nor attestation version identifies the protocol used to issue a particular certificate. No V1/V3 approval rule is inferred.
- Visibility limits: non-RKP/factory certificates and certificates without key 5 cannot provide these observations. Local validation can be intercepted on a compromised system. Metadata reflects the certificate's issuance context and does not establish the current build's CTS or Play Integrity state. No additional service access, network request or keystore operation is made.
- Result states: informational metadata present, key 5 absent, partial decoding (including missing required keys 1 or 4), unavailable decoding, unauthenticated chain. The last four do not mean CTS failure or absence of tampering.
- Interpretation: show diagnostic CBOR text only. APPROVED, NOT_APPROVED and future values never affect the verdict, tamper score or indicator counts. CTS status remains undetermined on all generations, including V3, until the server-side contract is documented and independently validated. When key 5 is displayed, the report and text export explicitly state that Fingerprint/VBMeta comparisons were not performed and that provisioning metadata may predate a system update.
- Validation: `./gradlew :feature:tee:data:unitTest :feature:tee:presentation:unitTest`. Parser fixtures cover nested/future fields, malformed and non-DER encodings, deeply constructed ASN.1, counts outside the model's range and decoding limits; analyzer tests cover trust, extension placement and root-nearest selection with leaf-added extensions; reducer tests verify informational severity, export and unchanged verdict/score.

The feature uses `com.upokecenter:cbor:4.5.6`, the latest stable Maven Central release inspected, through a feature-local parser. The [Java library](https://github.com/peteroupc/CBOR-Java) supports RFC 8949, Java 8 and the project's API 29 minimum; it is Unlicense/CC0 and brings `numbers:1.8.2` and `datautilities:1.1.0`. Its [map-decoding denial of service advisory](https://github.com/peteroupc/CBOR-Java/security/advisories/GHSA-fj2w-wfgv-mwq6) was fixed in 4.5.1; shared reference resolution remains disabled. The library bounds decoding nesting at 500. Library objects do not cross the parser boundary. Bouncy Castle already used by attestation handles ASN.1 wrapping. No latency or memory improvement is claimed.

#### Fingerprint and historical VBMeta comparison constraints

The following contracts describe different evidence sources; their field names and guarantees are not interchangeable. References use `android-16.0.0_r1` unless stated otherwise.

- [RemoteKeyProvisioning CborUtils.java](https://android.googlesource.com/platform/packages/modules/RemoteKeyProvisioning/+/android-16.0.0_r1/app/src/com/android/rkpdapp/utils/CborUtils.java), `buildUnverifiedDeviceInfo()`, places `Build.FINGERPRINT` in the CSR's unverified `fingerprint` entry. Server signing does not establish that this Android-side input was independently verified.
- The RKP HAL's [DeviceInfoV1](https://android.googlesource.com/platform/hardware/interfaces/+/android-16.0.0_r1/security/rkp/aidl/android/hardware/security/keymint/DeviceInfoV1.cddl), [DeviceInfoV2](https://android.googlesource.com/platform/hardware/interfaces/+/android-16.0.0_r1/security/rkp/aidl/android/hardware/security/keymint/DeviceInfoV2.cddl) and [DeviceInfoV3](https://android.googlesource.com/platform/hardware/interfaces/+/android-16.0.0_r1/security/rkp/aidl/android/hardware/security/keymint/DeviceInfoV3.cddl) define `vbmeta_digest` as an AVB-derived byte string, optional in V1 and required in V2/V3. These are request schemas, not X.509 provisioning-extension schemas.
- [VtsRemotelyProvisionedComponentTests.cpp](https://android.googlesource.com/platform/hardware/interfaces/+/android-16.0.0_r1/security/rkp/aidl/vts/functional/VtsRemotelyProvisionedComponentTests.cpp) generates a KeyMint attestation and a fresh `generateCertificateRequestV2` CSR in the same test and compares their AVB values, including `vbmeta_digest`. It does not compare an older server-issued certificate to the current boot or establish an invariant across OTA updates.
- The [public provisioning extension schema](https://source.android.com/docs/security/features/keystore/attestation#provisioning-information-extension), checked on 2026-10-25, defines keys 1, 4 and optional 6, with no key 5 field mapping, fingerprint or VBMeta guarantee. Authenticating an extension establishes the provenance of its bytes, not the semantics of undocumented nested keys. CSR-style names found inside key 5 also remain opaque diagnostic data.

Consequently no Fingerprint or historical VBMeta comparison is currently performed. The existing collector obtains certificates rather than the original authenticated CSR. A supported comparison needs an authoritative certificate field contract covering location, type, encoding, provenance and measurement context, plus representative authenticated certificate fixtures. A certificate validity date alone does not establish that provisioning and current attestation observed the same boot.

For a future implementation, absent fields, malformed encodings, unknown schemas, unauthenticated chains and unavailable current values must remain distinct from a completed comparison. Build updates and pre/post-OTA certificates require explicit historical-change handling. Even a confirmed historical difference must not alone raise FAIL, a tampering verdict or a CTS conclusion. Parser/analyzer tests already cover missing and malformed fields and trust gates; reducer regressions ensure apparent Fingerprint/VBMeta values remain INFO with unchanged verdict, score and indicator counts.

### Keystore behaviour probes

- Observable signal: the rows Key pair, AES-GCM, Lifecycle, KeyMint crypto, Timing, Oversized challenge, Keybox, ImportKey narrative, Pure cert, Pure cert level, Pure cert metadata, Update path, Update persistence, Pruning, Dual algorithm, Biometric TEE, StrongBox and ID attestation.
- Producing subsystem: the AndroidKeyStore provider in this process, keystore2, and the vendor KeyMint.
- Mechanism: each probe performs a keystore operation whose result a genuine stack fixes, for example a fresh signature that verifies against the leaf certificate.
- References: system/security keystore2/src/operation.rs (operation pruning, BACKEND_BUSY, MAX_RECEIVE_DATA, check_active); hardware/interfaces security/keymint IKeyMintOperation.aidl and KeyCreationResult.aidl (attestation IDs and patch level tags); frameworks/base core/java/android/content/pm/PackageManager.java (FEATURE_STRONGBOX_KEYSTORE).
- Applicability: deep checks run only when attestation reports a TEE or StrongBox tier.
- Visibility limits: the probes run in parallel with a probe that fills operation slots, so keystore2 may prune this app's own operations; a probe that throws therefore did not complete rather than failed.
- Result states: passed, failed, did not complete, skipped.
- Interpretation: only an observed contradiction is a failure; exceptions and skipped probes read "Did not complete" or "Skipped" at INFO.

### Operation error path

- Observable signal: the answers to updateAad on a signing operation, update with 0x8001 bytes, and update after abort, through keystore2's private binder.
- Producing subsystem: keystore2 for input length and finalized operations; the vendor KeyMint for updateAad.
- Mechanism: keystore2 rejects more than 0x8000 bytes and answers calls on finalized operations with INVALID_OPERATION_HANDLE itself; updateAad is forwarded to the vendor unchecked.
- References: system/security keystore2/src/operation.rs; hardware/interfaces IKeyMintOperation.aidl ("only applies to AEAD modes", no mandated error); system/keymint ta/src/operation.rs (the reference TA rejects it).
- Applicability: Android 12 and later; the known updateAad vendors are Samsung and Xiaomi on MediaTek.
- Visibility limits: the private binder path needs hidden API access; setup failures leave the probe incomplete.
- Result states: native-style errors, keystore2-enforced divergence, updateAad accepted, partially evaluated, did not complete.
- Interpretation: a keystore2-enforced divergence is a FAIL; updateAad acceptance outside the known vendors is a WARN, because the HAL permits it.

### Native process-side probes

- Observable signal: the binder ioctl in this process (GOT entry, prologue, honeypot timing), a TrickyStore-named mapping, leaf certificate DER fingerprints, tracing and syscall parity.
- Producing subsystem: this app process's libbinder and memory map.
- Mechanism: an interception module that hooks the binder ioctl in the app changes its GOT entry or prologue, or slows keystore-shaped transactions; its library appears in /proc/self/maps.
- References: Discovery only: the GOT, prologue, honeypot and DER signatures follow observed TrickyStore behaviour; TrickyStore's source was not reviewed here. The maps check reads /proc/self/maps as documented in kernel/common Documentation/filesystems/proc.rst.
- Applicability: all ABIs for the maps and DER checks; the prologue decoding is ABI specific.
- Visibility limits: a module that only runs inside keystore2 leaves this process untouched; if libduckdetector does not load, none of these probes run.
- Result states: detected, not detected, native probes did not run.
- Interpretation: the three ioctl observations are one finding and the maps hit another; when the native probes did not run, a consistent verdict reports SUPPORT instead of all-clear.

### Timing side channel and skip signatures

- Observable signal: getKeyEntry timing for attested and non-attested keys through keystore2's private binder, and the exception stacks captured when that measurement cannot start (the Timing side-channel row; TEE Simulator's legacy-database stack also marks the TEE Simulator generate-mode fingerprint row).
- Producing subsystem: keystore2 and any process intercepting its binder calls.
- Mechanism: an interception module that post-processes attested keys adds latency, and some modules answer with characteristic error codes and stacks.
- References: frameworks/base core/java/android/content/pm/PackageManager.java (FEATURE_KEYSTORE_APP_ATTEST_KEY). Discovery only: the TrickyStore and TEE Simulator stack signatures come from collected samples.
- Applicability: needs PURPOSE_ATTEST_KEY; devices that do not advertise app attestation keys are expected to refuse it.
- Visibility limits: timing varies with CPU frequency and load; the proxy numbering in the stack needles depends on this app's own proxy creation.
- Result states: measured, suspicious, skipped with a matched signature, skipped.
- Interpretation: the specific signatures are FAIL worded as matching a known keystore-interception module; the generic binder exception fallback applies only where app attestation keys are advertised.

### generateKey reply structure

- Observable signal: the reply keystore2 sends for this app's own generateKey call, read as a stable AIDL parcel (the TEE Simulator generate-mode fingerprint row).
- Producing subsystem: keystore2, which adds its own USER_ID to the KeyMint characteristics, the KeyMint behind it, and any process intercepting its binder calls.
- Mechanism: keystore2's store_new_key appends a SOFTWARE-level USER_ID after the KeyMint characteristics of every key it stores, so a reply without it as the last authorization was not assembled by keystore2; every AOSP KeyMint path returns CREATION_DATETIME at the KEYSTORE level.
- References: system/security keystore2/src/security_level.rs (store_new_key) and keystore2/src/km_compat/km_compat.cpp; system/keymint common/src/tag/info.rs and system/keymaster ng/AndroidKeyMintDevice.cpp (CREATION_DATETIME at KEYSTORE); hardware/interfaces security/keymint/aidl Tag.aidl (CREATION_DATETIME only has to be software-enforced); frameworks/native libs/binder/rust/src/parcel.rs (non-null markers and self-counting size headers).
- Applicability: keystore2, so Android 12 and later.
- Visibility limits: an interceptor that simulates KeyMint beneath keystore2 leaves keystore2's own reply intact, so these checks see only what the simulated KeyMint returns; the TEE Simulator samples come from earlier releases.
- Result states: matched, review, clean, unavailable.
- Interpretation: a reply keystore2 could not have assembled is FAIL; a CREATION_DATETIME outside KEYSTORE, which the KeyMint spec permits, is WARN.

### Keystore2 binder, grant and metadata probes

- Observable signal: the rows Grant isolated-domain, Grant caller binding, Grant access vector, Grant self-domain, Keystore2, Legacy keystore, Metadata key, Metadata shape, Binder hook, Patch mode, Binder chain and Cert post-processing.
- Producing subsystem: keystore2's IKeystoreService and IKeystoreSecurityLevel binder interfaces, and any process that intercepts them in this app or in keystore2.
- Mechanism: keystore2 fixes how grants bind to a grantee, which metadata getKeyEntry returns, and which binder objects answer; an interception layer that rebuilds these answers diverges from them.
- References: system/security keystore2/src/operation.rs for the operation semantics these probes share. The grant, metadata and binder expectations follow keystore2's AIDL as the probes implement it, and keystore2's grant and service code was not reviewed in this pass.
- Applicability: Android 12 and later with keystore2; grant probes need the isolated grantee service.
- Visibility limits: hidden API access and the isolated service must be available, or the probes report unavailable.
- Result states: consistent, diverged, crashed, unavailable, skipped.
- Interpretation: divergence is a supplementary FAIL or WARN by row; the dashboard picks the most specific grant finding.

### SOTER environment

- Observable signal: whether Tencent's SOTER service is reachable and can prepare keys and sessions, and whether its package is visible.
- Producing subsystem: the vendor SOTER Treble service and PackageManager.
- Mechanism: a likely SOTER device with a Simplified Chinese locale, no visible service package and no biometrics is an unusual environment.
- References: Discovery only: the SOTER behaviour follows Tencent's client library; package visibility follows frameworks/base PackageManager.java and the TEE module's own queries declaration.
- Applicability: devices in SoterSupportCatalog.
- Visibility limits: the query is declared in this module's manifest; BiometricManager needs USE_BIOMETRIC from the host.
- Result states: available, damaged, abnormal environment, skipped.
- Interpretation: WARN or FAIL as a supplementary indicator, never a policy verdict.

### SOTER reply integrity

- Observable signal: the ASK and AuthKey blobs the SOTER service exports to this app (their public key, signature, cpu_id and uid), and whether init reports the stock vendor.soter service as stopped while SOTER answers (the Soter and Soter reply integrity rows).
- Producing subsystem: Tencent's SOTER service, which forwards ISoterService calls to the vendor SOTER HAL and its TA, and any module that answers in their place.
- Mechanism: a TA exports a length-prefixed JSON followed by an RSA-PSS signature, and the JSON carries the TA's cpu_id, an anti-replay counter and the uid the caller passed; the probe sets SoterCoreTreble.uid, which defaults to 0, to this app's uid. OhMyKeymint's D-Soter mode answers inside the SOTER service process with D-Soter's fixed placeholder key, a 256-byte all-zero signature, cpu_id 0000000000000000, counter 0 and uid 0; its relay mode returns blobs made by the relay's own device, whose cpu_id and uid 0 ASK key were sampled; its software TA takes the HAL's service name after stopping vendor.soter. D-Soter's exact zero signature and zero cpu_id are reported as D-Soter markers, and the same all-zero values in other lengths separately; the signature is checked even when the JSON cannot be read. The cpu_id, uid and counter rules apply only to a blob that carries all three.
- References: system/sepolicy private/property_contexts and private/domain.te (init.svc.vendor.* is vendor_default_prop, which appdomain can read only where compatible properties are not enforced). Tencent soter 2.0.7 soter-core SoterCoreTreble, SoterCoreBase and SoterPubKeyModel, and its server-sample RSAUtil and example AuthKey. OhMyKeymint pif-spoof/src/soter/wire.rs, soter-ta/src/remote.rs, soter-ta/src/state.rs and template/soterta.sh.
- Applicability: devices whose SOTER service answers the probe; the vendor.soter check only where init.svc.vendor.soter is readable and the stock HAL runs under that service name.
- Visibility limits: only what the SOTER service returns is visible, so a module that signs with real keys and a plausible cpu_id, as OhMyKeymint's local software TA does, leaves no blob marker; the relay checks know only the relay OhMyKeymint fills in by default, and its uid 0 ASK key appears only when uid 0 is queried, while this probe queries its own uid; where compatible properties are enforced the vendor.soter state reads empty and that check stays silent.
- Result states: no marker, placeholder key, D-Soter zero signature, zero signature of another length, D-Soter zero cpu_id, zero cpu_id of another length, known relay cpu_id, known relay key, uid mismatch, cpu_id mismatch, non-positive counter, stock HAL stopped.
- Interpretation: the placeholder key and an all-zero signature of any length, which no RSA signing operation produces, are a supplementary FAIL; the other markers are a supplementary WARN; none of them changes the attestation verdict. No specification fixes a TA's first counter value, so a non-positive counter is a heuristic that has been checked against Tencent's sample and OhMyKeymint's TA but not against every vendor TA.

## Known gaps

- The oversized challenge probe treats any exception as a rejection; distinguishing a length rejection needs the KeyStoreException error code (API 33 and later).
- The update subcomponent probe matches exception message text to recognise key-not-found style failures.
- TeeCardModelMapper chooses the dashboard's top finding by matching report text; see docs/architecture/follow-ups.md.

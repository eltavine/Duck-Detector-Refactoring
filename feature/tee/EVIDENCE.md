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

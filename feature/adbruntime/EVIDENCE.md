# ADB Runtime evidence record

Status: reviewed

ADB Runtime correlates ADB control intent with runtime surfaces and the init service-status view.
Danger means a runtime surface that AOSP associates with a live or operational ADB path stayed
present while init.svc.adbd stayed stopped. It does not claim that resetprop, root, or a
particular hiding implementation caused the inconsistency.

## Version model

| Platform | AOSP lifecycle difference | Duck policy |
| --- | --- | --- |
| Android 10 / API 29 | AdbService forwards ADB_ENABLED to USB transport code. adbd can expose legacy TCP ADB and advertises it as _adb._tcp. Modern TLS Wireless Debugging does not exist. | Settings and the DNS-SD name are warning/context only. If init claims stopped, Duck may identify the local legacy listener by a minimal ADB CNXN/AUTH wire handshake; a stable protocol-confirmed listener can be hard contradiction evidence. |
| Android 11–15 / API 30–35 | AdbService introduces USB and Wi-Fi transport booleans plus startAdbdForTransport/stopAdbdForTransport. Modern _adb-tls-connect._tcp appears. UsbDeviceManager owns USB transport start/stop around gadget application. | Settings, USB gadget state, and DNS-SD names remain warning/context. A network endpoint becomes hard evidence only after the expected ADB first-packet protocol response is confirmed. |
| Android 16 / API 36 | UsbDeviceManager no longer calls startAdbdForTransport/stopAdbdForTransport. AdbService Settings observers call setAdbEnabled directly, which starts/stops adbd. Android 13 Test Harness behavior still exists. | Settings and USB gadget state remain warning/context. Legacy TCP must answer AUTH/CNXN and Wireless Debugging secure-connect must answer STLS before either can contradict init state. |
| Android 17 / API 37 | Android 17 keeps the Android 16 AdbService transport model and declares ACCESS_LOCAL_NETWORK as dangerous for local-network discovery. | Same protocol-confirmed runtime rules. mDNS is permission-limited without ACCESS_LOCAL_NETWORK. |

Fixed AOSP baselines used by the implementation:

- Android 10 android-10.0.0_r47: frameworks/base commit dff3deab5d25f8bbfd49abfb423043c9be47b7db; system/core commit 1dea9a052b7f214c10a77d5ed6ffd3602722a817.
- Android 11 android-11.0.0_r48: frameworks/base commit 1d9b9ab57d844b18b3b1b4297725141e7788109b; system/core commit 348efca472d810d3152568913da41a081893a4e3.
- Android 13 android-13.0.0_r83: frameworks/base commit 5c8d1d9774e465bb40d45096b2bc5eba77b261d6.
- Android 15 android-15.0.0_r36: frameworks/base commit 396d32905ded85c082232bc510b525c9e372e585.
- Android 16 android-16.0.0_r3: frameworks/base commit 33b96ce8a122757002e5040ac59824bd7a262e00; system/core commit 4deec4059670028cccb7f9f22bb73813ae71c6f3; packages/modules/adb commit cf10d3798f0847f89820381b541aedfd27a30375.
- Android 17 android-17.0.0_r1: frameworks/base commit 94b4c163b7dfe5ce3607f7bb8456f9573f7de57d; packages/modules/adb commit 9084198a2d4b0f6a0f174260fb42da33485b684d.
- Android 17 android-17.0.0_r1: packages/modules/Connectivity commit 347fbd34b368d19f0d87e908ea101eed3601a731.

Settings, init/property state, USB state, and network ADB discovery are sampled twice. The second
sample starts at least 1.5 seconds after the first sample starts. This interval is only a debounce
against one-shot transitions, not a claim that all AOSP USB recovery windows have expired. Hard
network findings additionally require the same endpoint to return the expected ADB protocol response
in both samples.

## Signals

### ADB root state

- Observable signal: service.adb.root=1.
- Producing subsystem: adbd privilege-drop logic and the Android property service.
- Mechanism: AOSP adbd reads service.adb.root in should_drop_privileges(); value 1 is the explicit adb-root request and on a debuggable build prevents privilege dropping, while value 0 is adb-unroot. Duck treats service.adb.root=1 itself as a danger-level privileged ADB request/state.
- References: Android 10 android-10.0.0_r47 system/core commit 1dea9a052b7f214c10a77d5ed6ffd3602722a817, daemon/main.cpp lines 87-106: https://android.googlesource.com/platform/system/core/+/1dea9a052b7f214c10a77d5ed6ffd3602722a817/adb/daemon/main.cpp#87 ; Android 16 android-16.0.0_r3 packages/modules/adb commit cf10d3798f0847f89820381b541aedfd27a30375, daemon/main.cpp lines 76-95: https://android.googlesource.com/platform/packages/modules/adb/+/cf10d3798f0847f89820381b541aedfd27a30375/daemon/main.cpp#76
- Applicability: service.adb.root semantics are stable across the supported AOSP generations checked here.
- Visibility limits: service.adb.root may be deleted or rewritten by a privileged property modifier; absence is therefore not proof that adbd is non-root.
- Result states: danger for service.adb.root=1; safe/context for service.adb.root=0; unavailable when the property cannot be observed.
- Interpretation: service.adb.root=1 proves an explicit privileged ADB request/state. Duck does not pretend to recover adbd credentials through procfs when the app sandbox cannot observe them.

### Settings and lifecycle context

- Observable signal: Settings.Global adb_enabled, Settings.Global adb_wifi_enabled, UserManager.DISALLOW_DEBUGGING_FEATURES, persist.sys.test_harness, and init.svc.adbd.
- Producing subsystem: SettingsProvider, framework AdbService, UserManager, Test Harness Mode, and init service-status properties.
- Mechanism: Settings express framework/user intent but are not daemon-liveness truth. Android 10 delegates state to transport code. Android 11–15 UsbDeviceManager explicitly starts/stops the USB transport around gadget application, but retry/fallback calls getAppliedFunctions() before setUsbConfig(), so ADB is re-added while the setting remains enabled; timeout fallback itself is therefore not used as evidence that Settings can legitimately disagree with daemon state. Android 16 moves the normal Settings path back to direct AdbService setAdbEnabled/startAdbd/stopAdbd. Settings are still not direct liveness observations, and they can be stale or intentionally non-equivalent to the ordinary USB transport state under DISALLOW_DEBUGGING_FEATURES and Android 13+ Test Harness Mode.
- References: Android 10 AdbService lines 263-277: https://android.googlesource.com/platform/frameworks/base/+/dff3deab5d25f8bbfd49abfb423043c9be47b7db/services/core/java/com/android/server/adb/AdbService.java#263 ; Android 11 UsbDeviceManager start/stop lines 1894-1916 and retry application lines 1925-1948: https://android.googlesource.com/platform/frameworks/base/+/1d9b9ab57d844b18b3b1b4297725141e7788109b/services/usb/java/com/android/server/usb/UsbDeviceManager.java#1894 ; Android 15 UsbDeviceManager start/stop lines 2494-2515 and retry application lines 2524-2555: https://android.googlesource.com/platform/frameworks/base/+/396d32905ded85c082232bc510b525c9e372e585/services/usb/java/com/android/server/usb/UsbDeviceManager.java#2494 ; Android 16 AdbService lines 188-197, 393-400, 473-477: https://android.googlesource.com/platform/frameworks/base/+/33b96ce8a122757002e5040ac59824bd7a262e00/services/core/java/com/android/server/adb/AdbService.java#188 ; Android 13 Test Harness lines 265-282: https://android.googlesource.com/platform/frameworks/base/+/5c8d1d9774e465bb40d45096b2bc5eba77b261d6/services/core/java/com/android/server/adb/AdbService.java#265
- Applicability: API 29 and later as context; adb_wifi_enabled and modern wireless transport semantics start at API 30; UsbDeviceManager transport ownership described above applies through API 35; the Test Harness shouldEnableAdbUsb exception starts at API 33.
- Visibility limits: unreadable Settings/restrictions/properties are unavailable; OEM policy can differ.
- Result states: enabled, disabled, restricted, test-harness, unavailable; Settings alone never create a hard contradiction.
- Interpretation: a normal, readable enabled setting contributes to warning-level ADB enabled. When DISALLOW_DEBUGGING_FEATURES is active, Settings are treated as non-authoritative; on API 33+ Test Harness Mode, ADB_ENABLED alone is also ignored because AOSP may force it to 1 independently of the ordinary USB transport boolean. Danger always requires an independent runtime surface below to disagree with init.

### USB runtime broadcast

- Observable signal: sticky android.hardware.usb.action.USB_STATE extras connected, configured, and function flags including adb.
- Producing subsystem: framework UsbDeviceManager in system_server plus the USB gadget state it tracks.
- Mechanism: AOSP builds broadcast function flags from applied USB functions, so adb=true is not process proof. Even configured=true is not daemon liveness: Android 16 configfs reacts to init.svc.adbd=stopped by clearing sys.usb.ffs.ready, while ffs.adb linkage/UDC setup lives in separate ready=1 actions. A configured gadget can therefore lag daemon state. Duck keeps USB_STATE entirely at warning/context severity.
- References: Android 10 broadcast lines 701-718 and getAppliedFunctions lines 786-793: https://android.googlesource.com/platform/frameworks/base/+/dff3deab5d25f8bbfd49abfb423043c9be47b7db/services/usb/java/com/android/server/usb/UsbDeviceManager.java#701 ; Android 16 broadcast lines 989-1006 and getAppliedFunctions lines 1193-1201: https://android.googlesource.com/platform/frameworks/base/+/33b96ce8a122757002e5040ac59824bd7a262e00/services/usb/java/com/android/server/usb/UsbDeviceManager.java#989 ; Android 16 configfs stopped/ready handling lines 14-24: https://android.googlesource.com/platform/system/core/+/4deec4059670028cccb7f9f22bb73813ae71c6f3/rootdir/init.usb.configfs.rc#14
- Applicability: API 29 and later AOSP USB device-management paths.
- Visibility limits: OEM USB implementations may change timing or broadcast behavior; no broadcast is unavailable rather than ADB-off evidence.
- Result states: warning/activity context when ADB USB function is visible, unavailable when not observable; USB_STATE alone never emits Danger.
- Interpretation: USB gadget state is useful corroboration and UI context, but Duck does not equate gadget configuration with adbd liveness.

### ADB property context

- Observable signal: init.svc.adbd, sys.usb.state, persist.sys.test_harness, and service.adb.root.
- Producing subsystem: init/property service, framework ADB service, USB init scripts, and adbd.
- Mechanism: init.svc.adbd is the property-side lifecycle operand for runtime contradiction rules. sys.usb.state is only an ADB activity hint, because USB gadget state can lag daemon state. persist.sys.test_harness changes how adb_enabled should be interpreted. service.adb.root has its own direct danger semantics described above. Other ADB/USB properties that do not add an independent decision are intentionally not duplicated into ADB Runtime.
- References: Android 13 Test Harness lines 265-282: https://android.googlesource.com/platform/frameworks/base/+/5c8d1d9774e465bb40d45096b2bc5eba77b261d6/services/core/java/com/android/server/adb/AdbService.java#265 ; Android 16 configfs stopped/ready handling lines 14-24: https://android.googlesource.com/platform/system/core/+/4deec4059670028cccb7f9f22bb73813ae71c6f3/rootdir/init.usb.configfs.rc#14
- Applicability: API 29 and later, with property readability varying by release and OEM.
- Visibility limits: ordinary app domains cannot read every property context; empty or denied reads are unavailable, and multiple readers of one property area are not independent trust domains.
- Result states: context/activity for sys.usb.state and Test Harness, direct danger for service.adb.root=1, and lifecycle state for init.svc.adbd.
- Interpretation: ADB Runtime keeps only properties that alter its verdict or explain a rule; redundant display-only properties stay in the System Properties detector instead.

### Network ADB mDNS

- Observable signal: API 29+ legacy _adb._tcp and API 30+ _adb-tls-connect._tcp resolved through NsdManager to an address owned by this device.
- Producing subsystem: adbd legacy TCP or Wireless Debugging listeners, mDNS/DNS-SD publishers, and Android NSD.
- Mechanism: Android 10 setup_port() advertises active legacy TCP ADB as _adb._tcp. Android 11 adds _adb-tls-connect._tcp for the secure-connect transport. Duck probes TLS first on API 30+ and falls back to legacy discovery; API 29 probes only legacy. The service type identifies a candidate endpoint, not the publisher's authority, so DNS-SD alone is warning/supporting evidence. If init claims stopped, the resolved local endpoint is passed to the ADB first-packet protocol probe below.
- References: Android 10 legacy type adb_mdns.h line 20: https://android.googlesource.com/platform/system/core/+/1dea9a052b7f214c10a77d5ed6ffd3602722a817/adb/adb_mdns.h#20 ; Android 10 setup_port/setup_mdns lines 182-187 and port selection 243-258: https://android.googlesource.com/platform/system/core/+/1dea9a052b7f214c10a77d5ed6ffd3602722a817/adb/daemon/main.cpp#182 ; Android 11 service-type definitions lines 27-29: https://android.googlesource.com/platform/system/core/+/348efca472d810d3152568913da41a081893a4e3/adb/adb_mdns.h#27 ; Android 16 TlsServer start followed by secure-connect advertisement daemon/adb_wifi.cpp lines 186-198: https://android.googlesource.com/platform/packages/modules/adb/+/cf10d3798f0847f89820381b541aedfd27a30375/daemon/adb_wifi.cpp#186 ; secure-connect mDNS registration daemon/mdns.cpp lines 204-212: https://android.googlesource.com/platform/packages/modules/adb/+/cf10d3798f0847f89820381b541aedfd27a30375/daemon/mdns.cpp#204 ; Android 17 NSD permission failure lines 1309-1317: https://android.googlesource.com/platform/packages/modules/Connectivity/+/347fbd34b368d19f0d87e908ea101eed3601a731/framework-t/src/android/net/nsd/NsdManager.java#1309
- Applicability: API 29 and later for _adb._tcp; API 30 and later additionally for _adb-tls-connect._tcp. Android 17 requires ACCESS_LOCAL_NETWORK for silent discovery.
- Visibility limits: discovery may be blocked by network policy, OEM changes, or missing Local Network permission. DNS-SD service names are protocol identifiers rather than an Android permission boundary, so a name alone never emits Danger.
- Result states: observed legacy or secure-connect local service, not observed, permission required, unavailable.
- Interpretation: mDNS tells Duck where to probe; the following ADB wire response establishes protocol identity.

### ADB wire protocol identity

- Observable signal: a local _adb._tcp endpoint accepts one A_CNXN packet and returns a structurally valid A_AUTH/ADB_AUTH_TOKEN or A_CNXN packet, or a local _adb-tls-connect._tcp endpoint returns a structurally valid A_STLS packet.
- Producing subsystem: the ADB transport protocol implemented by adbd, reached through the local address and port resolved from NSD.
- Mechanism: Duck only runs this probe when the same state sample says init.svc.adbd=stopped. It sends the AOSP initial A_CNXN frame with version 0x01000001, 4096-byte initial max payload, payload checksum, and command magic, then reads exactly one bounded response and closes. Legacy adbd answers with A_AUTH/ADB_AUTH_TOKEN when authentication is required or A_CNXN when it is not. Wireless Debugging secure-connect answers the same initial CNXN with A_STLS before any TLS handshake. Duck never sends ADB_AUTH_SIGNATURE, ADB_AUTH_RSAPUBLICKEY, an A_STLS reply, TLS handshake bytes, A_OPEN, or a service command.
- References: Android 10 protocol constants adb/adb.h lines 34-54: https://android.googlesource.com/platform/system/core/+/1dea9a052b7f214c10a77d5ed6ffd3602722a817/adb/adb.h#34 ; six-word message header adb/types.h lines 125-132: https://android.googlesource.com/platform/system/core/+/1dea9a052b7f214c10a77d5ed6ffd3602722a817/adb/types.h#125 ; legacy first-response decision adb/adb.cpp lines 294-307: https://android.googlesource.com/platform/system/core/+/1dea9a052b7f214c10a77d5ed6ffd3602722a817/adb/adb.cpp#294 ; AUTH token emission adb/daemon/auth.cpp lines 262-276: https://android.googlesource.com/platform/system/core/+/1dea9a052b7f214c10a77d5ed6ffd3602722a817/adb/daemon/auth.cpp#262 ; Android 16 A_STLS/version adb.h lines 49 and 61-62: https://android.googlesource.com/platform/packages/modules/adb/+/cf10d3798f0847f89820381b541aedfd27a30375/adb.h#49 ; TlsServer accepted sockets are registered with use_tls=true at daemon/adb_wifi.cpp lines 127-142: https://android.googlesource.com/platform/packages/modules/adb/+/cf10d3798f0847f89820381b541aedfd27a30375/daemon/adb_wifi.cpp#127 ; register_socket_transport stores use_tls at transport.cpp lines 1510-1520: https://android.googlesource.com/platform/packages/modules/adb/+/cf10d3798f0847f89820381b541aedfd27a30375/transport.cpp#1510 ; send_tls_request constructs A_STLS/A_STLS_VERSION at adb.cpp lines 318-324: https://android.googlesource.com/platform/packages/modules/adb/+/cf10d3798f0847f89820381b541aedfd27a30375/adb.cpp#318 ; initial CNXN chooses send_tls_request(t) when use_tls at lines 420-430: https://android.googlesource.com/platform/packages/modules/adb/+/cf10d3798f0847f89820381b541aedfd27a30375/adb.cpp#420 ; public-key authorization branch adb.cpp lines 462-490: https://android.googlesource.com/platform/packages/modules/adb/+/cf10d3798f0847f89820381b541aedfd27a30375/adb.cpp#462
- Applicability: API 29+ legacy plain TCP and API 30+ Wireless Debugging secure-connect endpoints advertised by the corresponding ADB mDNS service type.
- Visibility limits: requires NSD/local-network visibility and a reachable local endpoint. Connection refusal, timeout, malformed packets, or the wrong first packet remain not confirmed. Software can deliberately emulate the ADB protocol; in that case the device is genuinely exposing an ADB-compatible endpoint, which is still the runtime fact this detector is meant to surface.
- Result states: observed AUTH_TOKEN, CONNECT, or START_TLS; not confirmed; unavailable. A hard finding requires the same service kind and local address:port to confirm the expected ADB first packet in both samples while init.svc.adbd is stopped in both state samples.
- Interpretation: protocol confirmation is the network runtime identity used by hard contradiction rules. It replaces weaker port-occupancy and inaccessible procfs/socket-table heuristics.

## Severity semantics

- All clear: no active ADB signal and no contradiction was observed through available sources.
- Warning: ADB is enabled or supporting evidence indicates ADB activity, but there is no persistent hard runtime contradiction.
- Danger: service.adb.root=1, or a protocol-confirmed ADB network endpoint persists while init.svc.adbd persists as stopped.
- Info / unavailable: the app lacks enough visibility to evaluate a source.

Danger means the observed AOSP-defined runtime relationship is inconsistent. It intentionally does
not claim which component is wrong or why.

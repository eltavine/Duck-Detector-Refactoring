#!/usr/bin/env python3
"""Exercise a debug host and its canary only on a disposable Android emulator."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile

HOST = "com.eltavine.duckdetector"
OWNER = HOST + ".fixture.permissionowner"
PERMISSION = "me.weishu.kernelsu.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
TEST = HOST + ".InstallerCanaryRuntimeTest"
RUNNER = HOST + ".test/androidx.test.runner.AndroidJUnitRunner"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--test-apk", type=Path, required=True)
    parser.add_argument("--build-tools", default="37.0.0")
    parser.add_argument("--debug-keystore", type=Path, default=Path.home() / ".android/debug.keystore")
    args = parser.parse_args()
    if not args.serial.startswith("emulator-"):
        parser.error("Use a disposable emulator, never a personal device")
    tools = args.sdk / "build-tools" / args.build_tools
    platform = args.sdk / "platforms/android-37.0/android.jar"

    def run(*command, check=True):
        result = subprocess.run([str(x) for x in command], text=True, capture_output=True, check=False)
        if check and result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        return result.stdout + result.stderr

    def adb(*command, check=True):
        return run(args.sdk / "platform-tools/adb", "-s", args.serial, *command, check=check)

    def shell(*command, check=True):
        return adb("shell", *command, check=check)

    def instrument(expected, method="installationResultPreservesHostAndCleansSession"):
        result = shell("am", "instrument", "-w", "-e", "class", TEST + "#" + method,
                       "-e", "canaryExpected", expected, RUNNER)
        if "OK (1 test)" not in result:
            raise AssertionError(result)
        print("PASS", expected, method)

    version = re.search(r"versionCode='(\d+)'", run(tools / "aapt2", "dump", "badging", args.apk))[1]
    user = None
    with tempfile.TemporaryDirectory(prefix="installer-canary-fixtures-") as directory:
        directory = Path(directory)
        fixture_key = directory / "fixture.jks"
        # This temporary, public test credential is never used to sign the host application.
        run("keytool", "-genkeypair", "-keystore", fixture_key, "-alias", "fixture", "-storepass", "fixture-only",
            "-keypass", "fixture-only", "-dname", "CN=Permission owner fixture", "-keyalg", "RSA", "-validity", "1")

        def apk(name, permission=None, guard=False, fresh=False):
            manifest = directory / (name + ".xml")
            package = HOST + ".fixture.uidguard" if fresh else HOST if guard else OWNER
            shared = 'android:sharedUserId="android.uid.system"' if guard else ""
            declaration = f'<permission android:name="{permission}" android:protectionLevel="signature"/>' if permission else ""
            manifest.write_text(f'''<manifest xmlns:android="http://schemas.android.com/apk/res/android"
                package="{package}" android:versionCode="{int(version) + 1}" {shared}>
                <uses-sdk android:minSdkVersion="33" android:targetSdkVersion="37"/>
                {declaration}<application android:hasCode="false"/></manifest>''')
            unsigned = directory / (name + "-unsigned.apk")
            signed = directory / (name + ".apk")
            run(tools / "aapt2", "link", "-o", unsigned, "-I", platform, "--manifest", manifest)
            run(tools / "apksigner", "sign", "--ks", args.debug_keystore if guard else fixture_key,
                "--ks-key-alias", "androiddebugkey" if guard else "fixture", "--ks-pass",
                "pass:android" if guard else "pass:fixture-only", "--out", signed, unsigned)
            return signed

        retained = apk("retained", PERMISSION)
        rebuilt = apk("rebuilt", OWNER + ".DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION")
        guard = apk("uid-guard", guard=True)
        fresh_guard = apk("fresh-uid-guard", guard=True, fresh=True)
        try:
            adb("install", "-r", args.apk)
            adb("install", "-r", args.test_apk)
            adb("uninstall", OWNER, check=False)
            # AOSP returns 1 on success for this command; failures print a diagnostic.
            policy_result = shell("cmd", "package", "set-silent-updates-policy",
                                  "--allow-unlimited-silent-updates", HOST, check=False)
            if policy_result.strip():
                raise AssertionError(policy_result)
            instrument("disabled", "disabledProbeCreatesNoSession")
            shell("appops", "set", HOST, "REQUEST_INSTALL_PACKAGES", "deny")
            instrument("restricted")
            shell("appops", "set", HOST, "REQUEST_INSTALL_PACKAGES", "allow")
            instrument("absent")
            instrument("cancelled", "cancellationAbandonsOwnedSession")
            adb("install", retained)
            instrument(OWNER)
            result = shell("pm", "create-user", "installer-canary-fixture")
            user = re.search(r"Success: created user id (\d+)", result)[1]
            shell("pm", "install-existing", "--user", user, OWNER)
            shell("pm", "uninstall", "--user", "0", OWNER)
            instrument(OWNER)
            adb("uninstall", OWNER)
            adb("install", rebuilt)
            instrument("absent")
            # No target permission and no missing-group guard: only shared-UID continuity prevents replacement.
            result = adb("install", "-r", guard, check=False)
            if "INSTALL_FAILED_UID_CHANGED" not in result:
                raise AssertionError(result)
            installed = shell("dumpsys", "package", HOST)
            if f"versionCode={version} " not in installed:
                raise AssertionError("Host version changed after shared-UID rejection")
            print("PASS independent shared-UID rejection; host version preserved")
            result = adb("install", fresh_guard, check=False)
            if "INSTALL_FAILED_SHARED_USER_INCOMPATIBLE" not in result:
                raise AssertionError(result)
            if shell("pm", "path", HOST + ".fixture.uidguard", check=False).strip():
                raise AssertionError("Fresh-install guard fixture was installed")
            print("PASS independent fresh-install signer rejection")
        finally:
            adb("uninstall", HOST + ".fixture.uidguard", check=False)
            adb("uninstall", OWNER, check=False)
            if user:
                shell("pm", "remove-user", user, check=False)
            shell("cmd", "package", "set-silent-updates-policy", "--reset", check=False)
            shell("appops", "set", HOST, "REQUEST_INSTALL_PACKAGES", "default", check=False)


if __name__ == "__main__":
    main()

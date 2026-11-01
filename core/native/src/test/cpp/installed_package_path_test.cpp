// SPDX-License-Identifier: Apache-2.0
#include "common/installed_package_path.h"

#include <cassert>
#include <initializer_list>
#include <string>

using duckdetector::package_paths::without_install_tokens;

int main() {
    const std::string root = "/data/app/~~ZRBshrwXZYZRT9P94L6Zfw==/";
    const std::string package = "com.google.android.webview-EhjSUe61CRiru01kMjxgJw==";
    const std::string normalized = "/data/app/com.google.android.webview";
    for (const auto &suffix: {"/base.apk", "/oat/arm64/base.odex", "/oat/arm64/base.art",
                              "/oat/arm64/base.vdex", "/base.apk!/lib/arm64-v8a/libzygisk.so",
                              "/lib/arm64/libfrida-gadget.so", "/base.apk (deleted)"}) {
        assert(without_install_tokens(root + package + suffix) == normalized + suffix);
    }
    assert(without_install_tokens("[anon:dalvik-" + root + package + "/oat/arm64/base.art]") ==
           "[anon:dalvik-" + normalized + "/oat/arm64/base.art]");
    assert(without_install_tokens("/data/app/" + package + "/base.apk") == normalized + "/base.apk");
    assert(without_install_tokens("/mnt/expand/1234/app/~~ZRBshrwXZYZRT9P94L6Zfw==/" +
                                  package + "/base.apk") ==
           "/mnt/expand/1234/app/com.google.android.webview/base.apk");
    for (const std::string marker: {"Riru", "FRida", "gadget", "ZyGiSk", "MaGiSk", "KernelSU", "APatch"}) {
        const auto token = marker + std::string(22 - marker.size(), 'A') + "==";
        assert(without_install_tokens("/data/app/~~" + token + "/org.example-" + token + "/base.apk") ==
               "/data/app/org.example/base.apk");
    }
    // '-' is valid inside a token, so the package separator is not the last '-'.
    assert(without_install_tokens("/data/app/org.example-AAAAA-AAAAAAAAAAAAAAAA==/base.apk") ==
           "/data/app/org.example/base.apk");
    for (const std::string &path: std::initializer_list<std::string>{
            "", "/data/app/", "/data/app/~~riru/org.example-1/base.apk",
            "/data/app/org.example-riru/base.apk", "/data/app/org.example-1/base.apk",
            "/data/app/org.example-EhjSUe61CRiru01kMjxgJw==",
            "/data/app/org.example-EhjSUe61CRiru01kMjxgJw=/base.apk",
            "/data/adb/modules/riru/lib.so", "/memfd:frida (deleted)",
            "/mnt/expand/1234/not-app/" + package + "/base.apk",
    }) {
        assert(without_install_tokens(path) == path);
    }
    // Meaningful package names and filenames survive even when they contain a marker.
    assert(without_install_tokens(root + "org.riru.example-EhjSUe61CRiru01kMjxgJw==/base.apk") ==
           "/data/app/org.riru.example/base.apk");
    assert(without_install_tokens(root + package + "/EhjSUe61CRiru01kMjxgJw==") ==
           normalized + "/EhjSUe61CRiru01kMjxgJw==");
}

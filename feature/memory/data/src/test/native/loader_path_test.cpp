// SPDX-License-Identifier: Apache-2.0
#include "memory/common/maps_reader.h"
#include "memory/detectors/linker_detector.h"
#include "memory/detectors/signal_detector.h"

#include <link.h>
#include <signal.h>
#include <array>
#include <cassert>

extern "C" int dl_iterate_phdr(int (*)(dl_phdr_info *, size_t, void *), void *) {
    return 0;
}

void handler(int, siginfo_t *, void *) {}

int main() {
    using namespace duckdetector::memory;
    const std::string root = "/data/app/~~ZRBshrwXZYZRT9P94L6Zfw==/"
                             "com.google.android.webview-EhjSUe61CRiru01kMjxgJw==";
    const std::array<int, 4> watched{SIGTRAP, SIGBUS, SIGSEGV, SIGILL};
    std::array<struct sigaction, 4> previous{};
    struct sigaction action{};
    action.sa_flags = SA_SIGINFO;
    action.sa_sigaction = handler;
    sigemptyset(&action.sa_mask);
    for (size_t index = 0; index < watched.size(); ++index) {
        assert(sigaction(watched[index], &action, &previous[index]) == 0);
    }
    MapEntry entry;
    entry.start = reinterpret_cast<uintptr_t>(&handler);
    entry.end = entry.start + 1;
    entry.executable = true;
    entry.path = root + "/base.apk";
    assert(!is_suspicious_loader_path(entry.path));
    assert(detect_signal_anomalies({entry}).findings.empty());
    assert(detect_linker_anomalies({entry}).findings.empty());
    for (const auto *suffix: {"/oat/arm64/base.art", "/oat/arm64/base.vdex"}) {
        entry.executable = false;
        entry.path = root + suffix;
        assert(detect_linker_anomalies({entry}).findings.empty());
    }
    entry.path = "[anon:dalvik-" + root + "/oat/arm64/base.art]";
    assert(detect_linker_anomalies({entry}).findings.empty());
    entry.path = "[anon:dalvik-/data/app/~~ZRBshrwX...bview-EhjSUe61CRiru01kMjxgJw==/oat/arm64/base.art]";
    assert(detect_linker_anomalies({entry}).findings.empty());
    entry.executable = true;
    assert(detect_linker_anomalies({entry}).findings.empty());
    assert(detect_signal_anomalies({entry}).anonymous_handler);
    entry.executable = true;
    for (const std::string &path: std::initializer_list<std::string>{
            root + "/lib/arm64/libfrida-gadget.so", root + "/base.apk!/lib/arm64-v8a/libriru.so",
            "/data/adb/modules/zygisk/lib.so", "/data/local/tmp/libhook.so",
            "/data/app/org.example.riru-EhjSUe61CRiru01kMjxgJw==/base.apk",
    }) {
        entry.path = path;
        assert(is_suspicious_loader_path(path));
        const auto signals = detect_signal_anomalies({entry});
        assert(signals.findings.size() == 4);
        assert(signals.findings.front().detail.find(path) != std::string::npos);
        assert(detect_linker_anomalies({entry}).maps_only_module);
    }
    entry.path = "[anon:injected]";
    assert(detect_signal_anomalies({entry}).anonymous_handler);
    assert(detect_signal_anomalies({}).anonymous_handler);
    // A Frida substring in the opaque token must not bypass the path parser.
    entry.path = "/data/app/org.example-FRidaAAAAAAAAAAAAAAAAA==/base.apk";
    assert(detect_signal_anomalies({entry}).findings.empty());
    for (size_t index = 0; index < watched.size(); ++index) {
        assert(sigaction(watched[index], &previous[index], nullptr) == 0);
    }
}

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Injected native flow, JNI framing and IO tests; these do not validate an Android kernel."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[6]
NATIVE = ROOT / "capability/selinuxpolicy/data/src/main/cpp"
COMMON = ROOT / "core/native/src/main/cpp"
JNI = r"""
#include <string>
#define JNIEXPORT
#define JNICALL
using jstring = const char *;
using jobject = void *;
struct JNIEnv {
    std::string storage;
    jstring NewStringUTF(const char *value) { storage = value; return storage.c_str(); }
};
"""
FLOW = r"""
#include "selinuxpolicy/proc_attr_probe.h"
#include "jni.h"
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>
using namespace duckdetector::selinux::proc_attr;
static std::string mode;
static int targets_written, malformed_written, stock_written;
// Android 15 levelFrom=user assigns these categories to the primary user.
static const char kCarrierLevel[] = "u:r:app_zygote:s0:c512,c768";
extern "C" uid_t getuid()
#if defined(__linux__)
noexcept
#endif
{ return mode == "wrong_uid" ? 501 : 10000; }
namespace duckdetector::selinux::proc_attr {
int read_identity(char *buffer, unsigned) {
    if (mode == "unreadable") return EACCES;
    if (mode == "lost_identity" && targets_written) return ENOENT;
    const char *value = mode == "carrier_plain" || mode == "identity_added" ? kCarrier : kCarrierLevel;
    if (mode == "carrier_secondary") value = "u:r:app_zygote:s0:c513,c768";
    if (mode == "carrier_all") value = "u:r:app_zygote:s0:c123,c256,c512,c768";
    if (mode == "wrong_domain") value = "u:r:isolated_app:s0";
    if (mode == "domain_prefix") value = "u:r:app_zygote_extra:s0:c512,c768";
    if (mode == "wrong_role") value = "u:object_r:app_zygote:s0:c512,c768";
    if (mode == "level_prefix") value = "u:r:app_zygote:s00:c512,c768";
    if (mode == "empty_categories") value = "u:r:app_zygote:s0:";
    if (mode == "bad_categories") value = "u:r:app_zygote:s0:x512,c768";
    if (targets_written) {
        if (mode == "identity_changed") value = "u:r:isolated_app:s0";
        if (mode == "identity_categories") value = "u:r:app_zygote:s0:c513,c768";
        if (mode == "identity_removed") value = kCarrier;
        if (mode == "identity_added") value = kCarrierLevel;
    }
    strcpy(buffer, value);
    return 0;
}
WriteResult write_current(const char *value) {
    if (!strcmp(value, kMalformed)) {
        ++malformed_written;
        if (mode == "open_denied") return {EACCES, 0, -2};
        if (mode == "no_setcurrent") return {0, EACCES, -1};
        if (mode == "malformed_success") return {0, 0, 1};
        if (mode == "late_control" && malformed_written == 4) return {0, EINTR, -1};
        return {0, EINVAL, -1};
    }
    if (!strcmp(value, kCarrier)) {
        ++stock_written;
        if (mode == "stock_invalid") return {0, EINVAL, -1};
        if (mode == "stock_success") return {0, 0, 0};
        return {0, EACCES, -1};
    }
    ++targets_written;
    if (mode == "success") return {0, 0, static_cast<int64_t>(strlen(value))};
    if (mode == "short_write") return {0, 0, 1};
    if (mode == "zero_write") return {0, 0, 0};
    if (mode == "target_open") return {ENOENT, 0, -2};
    if (mode == "target_eperm") return {0, EPERM, -1};
    if (mode == "target_eintr") return {0, EINTR, -1};
    if (!strcmp(value, targets[0].context) && (mode == "recognized" ||
        (mode == "unstable" && targets_written <= 9))) return {0, EACCES, -1};
    return {0, EINVAL, -1};
}
}
namespace duckdetector::common::detail {
ChildOutcome run_disposable_child(std::span<unsigned char> report, ChildDeadlines deadlines,
                                 ChildBody body, const void *context) {
    assert(deadlines.run.count() == 1000 && deadlines.reap.count() == 250);
    if (mode == "not_started") return {.end = ChildEnd::kNotStarted, .error = EAGAIN};
    if (mode == "setup_failed") return {.end = ChildEnd::kSetupFailed};
    // Synchronous injection verifies framing and flow, not the production fork/timeout implementation.
    FILE *file = tmpfile();
    assert(file);
    const int status = body(context, fileno(file));
    const long length = lseek(fileno(file), 0, SEEK_CUR);
    assert(length > 0 && static_cast<size_t>(length) <= report.size());
    lseek(fileno(file), 0, SEEK_SET);
    assert(read(fileno(file), report.data(), length) == length);
    fclose(file);
    return {.end = mode == "timeout" ? ChildEnd::kTimedOut : mode == "signal" ? ChildEnd::kSignaled :
        mode == "seccomp" ? ChildEnd::kSeccompTrapped : mode == "unreaped" ? ChildEnd::kNotReaped : ChildEnd::kExited,
        .exit_status = mode == "failed_exit" ? 1 : status, .signal = mode == "signal" ? 9 : 0,
        .report_length = mode == "truncated" ? 1u : static_cast<size_t>(length - (mode == "partial" ? 1 : 0))};
}
}
extern "C" jstring Java_com_eltavine_duckdetector_capability_selinuxpolicy_data_SelinuxProcAttrCurrentProbe_nativeCollectProcAttr(JNIEnv *, jobject);
static void reset(const char *test) {
    mode = test;
    targets_written = malformed_written = stock_written = 0;
}
int main() {
    for (const char *test : {"stock", "carrier_plain", "carrier_secondary", "carrier_all", "recognized", "unstable", "target_open", "target_eperm", "target_eintr",
        "wrong_uid", "wrong_domain", "domain_prefix", "wrong_role", "level_prefix", "empty_categories", "bad_categories", "unreadable", "open_denied", "no_setcurrent", "malformed_success",
        "stock_invalid", "stock_success", "late_control", "success", "short_write", "zero_write",
        "identity_changed", "identity_categories", "identity_removed", "identity_added", "lost_identity", "not_started", "setup_failed", "timeout", "signal", "seccomp",
        "unreaped", "failed_exit", "truncated", "partial"}) {
        reset(test);
        const auto result = collect();
        const bool complete = mode == "stock" || mode == "carrier_plain" || mode == "carrier_secondary" || mode == "carrier_all" || mode == "recognized" ||
            mode == "unstable" || mode == "target_open" || mode == "target_eperm" || mode == "target_eintr";
        assert((result.report.state == State::kComplete) == complete);
        if (complete) assert(result.report.completed_rounds == 2 && targets_written == 18 &&
            malformed_written == 4 && stock_written == 4);
        if (mode == "wrong_uid" || mode == "wrong_domain" || mode == "domain_prefix" || mode == "wrong_role" ||
            mode == "level_prefix" || mode == "empty_categories" || mode == "bad_categories")
            assert(result.report.state == State::kUnsupported && targets_written == 0 && !malformed_written && !stock_written);
        if (mode == "unreadable" || mode == "not_started" || mode == "setup_failed")
            assert(result.report.state == State::kUnavailable);
        if (mode == "open_denied" || mode == "no_setcurrent")
            assert(result.report.state == State::kPermissionLimited && targets_written == 0);
        if (mode == "success" || mode == "short_write" || mode == "zero_write" || mode == "identity_changed" || mode == "identity_categories" ||
            mode == "identity_removed" || mode == "identity_added" ||
            mode == "lost_identity") assert(targets_written == 1);
        if (mode == "identity_changed" || mode == "identity_categories" || mode == "identity_removed" || mode == "identity_added")
            assert(result.report.identity_changed);
        if (mode == "target_open") assert(result.report.writes[0][0].open_error == ENOENT &&
            result.report.writes[0][0].bytes == -2);
        reset(test);
        JNIEnv env;
        const std::string payload = Java_com_eltavine_duckdetector_capability_selinuxpolicy_data_SelinuxProcAttrCurrentProbe_nativeCollectProcAttr(&env, nullptr);
        assert(payload.starts_with("SCHEMA=1\nRESULT=Controls\t\t") && payload.size() < 32768);
        assert((payload.find("CONTROLS_PASSED") != std::string::npos) == complete);
        assert((payload.find("CONTEXT_RECOGNIZED") != std::string::npos) == (mode == "recognized"));
        if (mode == "recognized") assert(payload.find("RESULT=KernelSU\tu:r:ksu:s0\tCONTEXT_RECOGNIZED") != std::string::npos);
        assert(payload.find("RESULT=KernelSU file\tu:object_r:ksu_file:s0\t") != std::string::npos);
        if (!complete) assert(payload.find("NORMAL_EINVAL") == std::string::npos);
    }
}
"""
IO = r"""
#include "selinuxpolicy/proc_attr_probe.h"
#include <cassert>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
static int open_error, io_error, io_calls, close_calls, read_calls;
static ssize_t returned;
static const char *read_value;
int test_open(const char *path, int flags) {
    assert(!strcmp(path, "/proc/thread-self/attr/current"));
    assert(flags == (O_RDONLY | O_CLOEXEC) || flags == (O_WRONLY | O_CLOEXEC));
    if (open_error) { errno = open_error; return -1; }
    return 42;
}
ssize_t test_read(int fd, void *buffer, size_t size) {
    assert(fd == 42);
    ++read_calls;
    if (read_calls == 1 && io_error == EINTR) { errno = EINTR; return -1; }
    assert(strlen(read_value) <= size);
    memcpy(buffer, read_value, strlen(read_value));
    return strlen(read_value);
}
ssize_t test_write(int fd, const void *buffer, size_t size) {
    assert(fd == 42 && size == strlen(static_cast<const char *>(buffer)));
    ++io_calls;
    errno = io_error;
    return returned;
}
int test_close(int fd) { assert(fd == 42); ++close_calls; errno = EBADF; return -1; }
#define open test_open
#define read test_read
#define write test_write
#define close test_close
#include "selinuxpolicy/proc_attr_io.cpp"
#undef open
#undef read
#undef write
#undef close
int main() {
    using namespace duckdetector::selinux::proc_attr;
    open_error = EACCES;
    auto result = write_current(kCarrier);
    assert(result.open_error == EACCES && result.bytes == -2 && !io_calls && !close_calls);
    open_error = 0;
    for (int error : {EACCES, EPERM, EINVAL, EINTR}) {
        io_error = error;
        returned = -1;
        io_calls = close_calls = 0;
        result = write_current(kCarrier);
        assert(result.open_error == 0 && result.write_error == error && result.bytes == -1);
        assert(io_calls == 1 && close_calls == 1); // even EINTR must not repeat a transaction
    }
    for (ssize_t count : {0, 1, 17}) {
        returned = count;
        result = write_current(kCarrier);
        assert(result.write_error == 0 && result.bytes == count); // close errno must not alter the write
    }
    char buffer[128]{};
    read_value = "u:r:app_zygote:s0\n";
    io_error = EINTR;
    read_calls = 0;
    assert(read_identity(buffer, sizeof(buffer)) == 0 && !strcmp(buffer, kCarrier) && read_calls == 2);
    read_value = "";
    assert(read_identity(buffer, sizeof(buffer)) == EINVAL);
    assert(read_identity(buffer, 1) == EINVAL);
    open_error = ENOENT;
    assert(read_identity(buffer, sizeof(buffer)) == ENOENT);
}
"""

class ProcAttrNativeTest(unittest.TestCase):
    def compile_and_run(self, harness, sources):
        compiler = os.environ.get("CXX") or shutil.which("clang++") or shutil.which("g++")
        self.assertIsNotNone(compiler, "Host C++20 compiler required")
        with tempfile.TemporaryDirectory(prefix="duck-proc-attr-native-") as directory:
            path = Path(directory)
            (path / "test.cpp").write_text(harness)
            (path / "jni.h").write_text(JNI)
            command = [compiler, "-std=c++20", "-Wall", "-Wextra", "-Werror", "-I", str(path),
                       "-I", str(NATIVE), "-I", str(COMMON), str(path / "test.cpp"), *map(str, sources),
                       "-o", str(path / "test")]
            subprocess.run(command, check=True, timeout=60)
            subprocess.run([str(path / "test")], check=True, timeout=10)

    def test_control_flow_and_native_payload(self):
        self.compile_and_run(FLOW, [NATIVE / "selinuxpolicy/proc_attr_probe.cpp",
                                   NATIVE / "selinuxpolicy/proc_attr_native_bridge.cpp",
                                   COMMON / "common/payload_codec.cpp"])

    def test_transaction_errors_and_thread_identity_path(self):
        self.compile_and_run(IO, [])

if __name__ == "__main__":
    unittest.main()

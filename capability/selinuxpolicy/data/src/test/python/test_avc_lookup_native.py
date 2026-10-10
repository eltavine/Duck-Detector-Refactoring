#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Injected AVC lookup parser, flow, JNI framing and IO tests; these do not validate an Android kernel."""
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
#include "selinuxpolicy/avc_lookup_probe.h"
#include "jni.h"
#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>
using namespace duckdetector::selinux::avc_lookup;
using duckdetector::common::ChildEnd;
static std::string mode;
static uint32_t counters[kCpuLimit];
static int pinned;
static unsigned writes, identity_reads, stats_reads;
static uint64_t clock_ns;
// Android 15 levelFrom=user assigns these categories to the primary user.
static const char kCarrierLevel[] = "u:r:app_zygote:s0:c512,c768";
static bool sparse() { return mode == "sparse"; }
extern "C" uid_t getuid()
#if defined(__linux__)
noexcept
#endif
{ return mode == "wrong_uid" ? 1000 : 10123; }
namespace duckdetector::selinux::avc_lookup {
int read_identity(char *context, unsigned capacity) {
    ++identity_reads;
    if (mode == "identity_unreadable") return EACCES;
    const char *value = mode == "carrier_plain" || mode == "identity_added" ? kCarrier : kCarrierLevel;
    if (mode == "carrier_secondary") value = "u:r:app_zygote:s0:c513,c768";
    if (mode == "carrier_all") value = "u:r:app_zygote:s0:c123,c256,c512,c768";
    if (mode == "wrong_domain") value = "u:r:isolated_app:s0";
    if (mode == "domain_prefix") value = "u:r:app_zygote_extra:s0:c512,c768";
    if (mode == "wrong_role") value = "u:object_r:app_zygote:s0:c512,c768";
    if (mode == "level_prefix") value = "u:r:app_zygote:s00:c512,c768";
    if (mode == "empty_categories") value = "u:r:app_zygote:s0:";
    if (mode == "bad_categories") value = "u:r:app_zygote:s0:x512,c768";
    if (identity_reads > 1) {
        if (mode == "identity_changed") value = "u:r:isolated_app:s0";
        if (mode == "identity_categories") value = "u:r:app_zygote:s0:c513,c768";
        if (mode == "identity_removed") value = kCarrier;
        if (mode == "identity_added") value = kCarrierLevel;
    }
    assert(strlen(value) < capacity);
    strcpy(context, value);
    return 0;
}
int read_text(const char *path, char *buffer, size_t capacity, size_t &length) {
    std::string text;
    if (!strcmp(path, kEnforce)) {
        if (mode == "enforce_unreadable") return EACCES;
        text = mode == "permissive" ? "0" : "1";
    } else if (!strcmp(path, kPossibleCpus)) {
        if (mode == "no_possible") return ENOENT;
        text = sparse() ? "0-1,4-5\n" : mode == "bad_possible" ? "0-x\n" : "0-7\n";
    } else {
        assert(!strcmp(path, kStats));
        if (mode == "no_stats") return ENOENT;
        ++stats_reads;
        // The read's own path walk queries the AVC on this CPU before its row is printed.
        if (pinned >= 0) counters[pinned] += 6;
        text = mode == "bad_header" ? "lookups misses hits allocations reclaims frees\n"
                                    : "lookups hits misses allocations reclaims frees\n";
        const unsigned rows = sparse() ? 4 : mode == "rows_mismatch" ? 7 : 8;
        for (unsigned row = 0; row < rows; ++row) {
            const uint32_t lookups = counters[sparse() && row >= 2 ? row + 2 : row], misses = 9;
            const uint32_t hits = mode == "bad_sum" ? lookups : lookups - misses;
            text += std::to_string(lookups) + " " + std::to_string(hits) + " " + std::to_string(misses) + " 3 0 1\n";
        }
    }
    if (text.size() >= capacity) return EOVERFLOW;
    memcpy(buffer, text.data(), text.size());
    length = text.size();
    return 0;
}
int open_attr(int &fd) {
    if (mode == "open_denied") return EACCES;
    if (mode == "open_missing") return ENOENT;
    fd = 42;
    return 0;
}
WriteOutcome write_payload(int fd, const char *payload) {
    // Namespace-scope constexpr arrays have internal linkage, so compare contents, not addresses.
    const bool a = !strcmp(payload, kPayloadA);
    assert(fd == 42 && (a || !strcmp(payload, kPayloadB)));
    ++writes;
    clock_ns += a ? 300 : 200;
    if (mode == "no_setcurrent") return {EACCES, -1};
    if (mode == "control_success" && writes == 1) return {0, static_cast<int64_t>(kPayloadLength)};
    if (mode == "control_b_eperm" && writes == 2) return {EPERM, -1};
    if (mode == "timing_eintr" && writes == 50) return {EINTR, -1};
    if (mode == "counting_short" && writes == 2 + 2 * (kWarmup + kPairs) + 5000) return {0, 3};
    if (pinned >= 0) counters[pinned] += a ? (mode == "two_two" ? 2 : 1) : (mode == "one_two" || mode == "two_two" ? 2 : 1);
    return {EINVAL, -1};
}
void close_attr(int fd) { assert(fd == 42); }
int now_ns(uint64_t &value) {
    if (mode == "clock_failed") return EINVAL;
    value = ++clock_ns;
    return 0;
}
int pin_to_allowed_cpu(int &cpu) {
    cpu = -1;
    if (mode == "affinity_failed") return EPERM;
    cpu = pinned = sparse() ? 4 : 2;
    return 0;
}
int verify_pinned(int cpu) {
    assert(cpu == pinned);
    return mode == "migrated" && stats_reads >= 4 ? EXDEV : 0;
}
}
namespace duckdetector::common::detail {
ChildOutcome run_disposable_child(std::span<unsigned char> report, ChildDeadlines deadlines,
                                 ChildBody body, const void *context) {
    assert(deadlines.run.count() == 2000 && deadlines.reap.count() == 250);
    if (mode == "not_started") return {.end = ChildEnd::kNotStarted, .error = EAGAIN};
    if (mode == "setup_failed") return {.end = ChildEnd::kSetupFailed};
    // Synchronous injection verifies framing and flow, not the production fork/timeout implementation.
    FILE *file = tmpfile();
    assert(file);
    const int status = body(context, fileno(file));
    const long written = lseek(fileno(file), 0, SEEK_CUR);
    assert(written > 0 && written % static_cast<long>(sizeof(Report)) == 0);
    assert(written / static_cast<long>(sizeof(Report)) <= 13);
    const size_t kept = std::min(static_cast<size_t>(written), report.size());
    lseek(fileno(file), 0, SEEK_SET);
    assert(read(fileno(file), report.data(), kept) == static_cast<ssize_t>(kept));
    fclose(file);
    return {.end = mode == "timeout" ? ChildEnd::kTimedOut : mode == "signal" ? ChildEnd::kSignaled :
        mode == "seccomp" ? ChildEnd::kSeccompTrapped : mode == "unreaped" ? ChildEnd::kNotReaped : ChildEnd::kExited,
        .exit_status = mode == "failed_exit" ? 1 : status, .signal = mode == "signal" ? 9 : 0,
        .report_length = mode == "partial" ? kept - 1 : kept};
}
}
extern "C" jstring Java_com_eltavine_duckdetector_capability_selinuxpolicy_data_SelinuxAvcLookupProbe_nativeCollectAvcLookup(JNIEnv *, jobject);
static void reset(const char *test) {
    mode = test;
    // Counters start just below the 32-bit wrap, so every batch delta needs modular arithmetic.
    std::fill(std::begin(counters), std::end(counters), 0xFFFFF000u);
    pinned = -1;
    writes = identity_reads = stats_reads = 0;
    clock_ns = 1000;
}
static void parsers() {
    CacheStats stats;
    const std::string header = "lookups hits misses allocations reclaims frees\n";
    const std::string good = header + "10 7 3 1 0 0\n4294967295 4294967290 5 0 0 0\n2 4294967293 5 0 0 0\n";
    assert(parse_cache_stats(good.data(), good.size(), stats) == 0 && stats.rows == 3);
    assert(stats.lookups[0] == 10 && stats.lookups[1] == 4294967295u && stats.lookups[2] == 2);
    for (const std::string &bad : {std::string("lookups hits misses allocations reclaims\n10 7 3 1 0\n"),
            header + "10 7 3 1 0 0", header + "10 7 3 1 0\n", header + "10 7 3 1 0 0 0\n",
            header + "10 8 3 1 0 0\n", header + " 10 7 3 1 0 0\n", header + "4294967296 4294967293 3 0 0 0\n",
            header + "-1 0 0 0 0 0\n", header + "10 7 3 1 0 0\n\n"}) {
        assert(parse_cache_stats(bad.data(), bad.size(), stats) == EPROTO);
    }
    assert(parse_cache_stats(header.data(), header.size(), stats) == ENODATA);
    std::string many = header;
    for (unsigned row = 0; row <= kCpuLimit; ++row) many += "1 1 0 0 0 0\n";
    assert(parse_cache_stats(many.data(), many.size(), stats) == E2BIG);

    CpuMask mask;
    const auto list = [&mask](const char *text) { return parse_cpu_list(text, strlen(text), mask); };
    assert(list("0-7\n") == 0 && mask.count == 8 && stats_row(mask, 5) == 5);
    assert(list("0\n") == 0 && mask.count == 1 && stats_row(mask, 0) == 0 && stats_row(mask, 1) == -1);
    assert(list("0-1,4-5\n") == 0 && mask.count == 4 && stats_row(mask, 4) == 2 && stats_row(mask, 5) == 3);
    assert(stats_row(mask, 2) == -1 && stats_row(mask, -1) == -1 && stats_row(mask, kCpuLimit) == -1);
    assert(list("0-3,6") == 0 && mask.count == 5);
    for (const char *bad : {"", "\n", "7-3\n", "0-3,2-5\n", "0-3,3\n", "a\n", "0-\n", "0,,1\n", "0-3\n\n", "0 1\n"})
        assert(list(bad) == EPROTO);
    assert(list("0-256\n") == E2BIG);
}
static void expect(const char *test, State state, Step step, int error) {
    reset(test);
    const Result result = collect();
    const Report &report = result.report;
    assert(report.state == state && report.step == step && report.error == error);
    const bool counted = state == State::kCollected;
    const uint32_t a = mode == "two_two" ? 8198 : 4102, b = mode == "one_two" || mode == "two_two" ? 8198 : 4102;
    if (counted || report.identity_changed) {
        assert(report.rounds == kRounds && report.pairs == kPairs && writes == 2 + 2 * (kWarmup + kPairs) + 2 * kRounds * kWrites);
        assert(report.cpu == (sparse() ? 4 : 2) && report.cpu_row == 2 && report.cpu_rows == (sparse() ? 4u : 8u));
        assert(report.possible_cpus == report.cpu_rows && stats_reads == 1 + 4 * kRounds);
        for (unsigned round = 0; round < kRounds; ++round) assert(report.batch_a[round] == a && report.batch_b[round] == b);
        assert(report.median_a_ns == 301 && report.median_b_ns == 201 && report.median_delta_ns == 100);
    }
    if (counted) assert(report.unexpected == Payload::kNone && !report.identity_changed && identity_reads == 2);
    if (state == State::kTimingOnly) assert(report.pairs == kPairs && report.unexpected == Payload::kNone);
}
int main() {
    parsers();
    for (const char *test : {"stock", "one_two", "two_two", "sparse", "carrier_plain", "carrier_secondary", "carrier_all"}) expect(test, State::kCollected, Step::kFinished, 0);
    expect("wrong_uid", State::kUnsupported, Step::kCarrier, 0);
    for (const char *test : {"wrong_domain", "domain_prefix", "wrong_role", "level_prefix", "empty_categories", "bad_categories"}) {
        expect(test, State::kUnsupported, Step::kCarrier, 0);
        assert(writes == 0 && stats_reads == 0 && identity_reads == 1);
    }
    expect("identity_unreadable", State::kUnavailable, Step::kCarrier, EACCES);
    expect("permissive", State::kUnsupported, Step::kEnforce, 0);
    expect("enforce_unreadable", State::kUnavailable, Step::kEnforce, EACCES);
    expect("open_denied", State::kPermissionLimited, Step::kOpen, EACCES);
    expect("open_missing", State::kUnavailable, Step::kOpen, ENOENT);
    assert(writes == 0);
    expect("no_setcurrent", State::kPermissionLimited, Step::kControls, EACCES);
    assert(writes == 1 && collect().report.unexpected == Payload::kA);
    expect("control_success", State::kInconclusive, Step::kControls, 0);
    reset("control_success");
    const Report accepted = collect().report;
    assert(writes == 1 && accepted.unexpected == Payload::kA && accepted.unexpected_bytes == kPayloadLength);
    expect("control_b_eperm", State::kPermissionLimited, Step::kControls, EPERM);
    expect("timing_eintr", State::kInconclusive, Step::kTiming, EINTR);
    expect("clock_failed", State::kInconclusive, Step::kTiming, EINVAL);
    expect("counting_short", State::kInconclusive, Step::kCounting, 0);
    reset("counting_short");
    const Report short_write = collect().report;
    assert(short_write.unexpected == Payload::kB && short_write.unexpected_bytes == 3 && short_write.rounds == 0);
    expect("affinity_failed", State::kTimingOnly, Step::kAffinity, EPERM);
    expect("no_possible", State::kTimingOnly, Step::kCpuMap, ENOENT);
    expect("bad_possible", State::kTimingOnly, Step::kCpuMap, EPROTO);
    expect("no_stats", State::kTimingOnly, Step::kStats, ENOENT);
    expect("bad_header", State::kTimingOnly, Step::kStats, EPROTO);
    expect("bad_sum", State::kTimingOnly, Step::kStats, EPROTO);
    expect("rows_mismatch", State::kTimingOnly, Step::kStats, EPROTO);
    expect("migrated", State::kTimingOnly, Step::kCounting, EXDEV);
    for (const char *test : {"identity_changed", "identity_categories", "identity_removed", "identity_added"}) {
        expect(test, State::kInconclusive, Step::kIdentity, 0);
        reset(test);
        assert(collect().report.identity_changed);
    }
    expect("not_started", State::kUnavailable, Step::kCarrier, EAGAIN);
    expect("setup_failed", State::kUnavailable, Step::kCarrier, 0);
    // These children ran to completion in the injection, so only the outcome may override the record.
    for (const char *test : {"timeout", "signal", "seccomp", "unreaped", "failed_exit", "partial"}) {
        expect(test, State::kInconclusive, test == std::string("partial") ? Step::kCounting : Step::kFinished, 0);
    }
    const auto payload = [](const char *test) {
        reset(test);
        JNIEnv env;
        return std::string(Java_com_eltavine_duckdetector_capability_selinuxpolicy_data_SelinuxAvcLookupProbe_nativeCollectAvcLookup(&env, nullptr));
    };
    const std::string one_two = payload("one_two");
    assert(one_two.starts_with("SCHEMA=1\nSTATE=COLLECTED\nSTEP=FINISHED\nERRNO=0\nUNEXPECTED_PAYLOAD=NONE\n"));
    for (const char *line : {"\nCPU=2\nCPU_ROW=2\nCPU_ROWS=8\nPOSSIBLE_CPUS=8\nPAIRS=128\nROUNDS=4\nWRITES=4096\n",
            "\nBATCH_A=4102,4102,4102,4102\nBATCH_B=8198,8198,8198,8198\n",
            "\nMEDIAN_A_NS=301\nMEDIAN_B_NS=201\nMEDIAN_DELTA_NS=100\n",
            "\nCHILD_END=EXITED\nCHILD_EXIT=0\nCHILD_SIGNAL=0\nCHILD_ERRNO=0\n"}) {
        assert(one_two.find(line) != std::string::npos);
    }
    assert(payload("timeout").find("\nSTATE=INCONCLUSIVE\n") != std::string::npos);
    assert(payload("timeout").find("\nCHILD_END=TIMED_OUT\n") != std::string::npos);
    const std::string not_started = "\nSTATE=UNAVAILABLE\nSTEP=CARRIER\nERRNO=" + std::to_string(EAGAIN) + "\n";
    assert(payload("not_started").find(not_started) != std::string::npos);
    assert(payload("no_setcurrent").find("\nUNEXPECTED_PAYLOAD=A\nUNEXPECTED_RETURNED=-1\n") != std::string::npos);
    const std::string no_stats = "\nSTATE=TIMING_ONLY\nSTEP=STATS\nERRNO=" + std::to_string(ENOENT) + "\n";
    assert(payload("no_stats").find(no_stats) != std::string::npos);
}
"""
IO = (Path(__file__).resolve().parents[1] / "cpp/avc_lookup_io_test.cpp").read_text()


class AvcLookupNativeTest(unittest.TestCase):
    def compile_and_run(self, harness, sources):
        compiler = os.environ.get("CXX") or shutil.which("clang++") or shutil.which("g++")
        self.assertIsNotNone(compiler, "Host C++20 compiler required")
        with tempfile.TemporaryDirectory(prefix="duck-avc-lookup-native-") as directory:
            path = Path(directory)
            (path / "test.cpp").write_text(harness)
            (path / "jni.h").write_text(JNI)
            command = [compiler, "-std=c++20", "-Wall", "-Wextra", "-Werror", "-I", str(path),
                       "-I", str(NATIVE), "-I", str(COMMON), str(path / "test.cpp"), *map(str, sources),
                       "-o", str(path / "test")]
            subprocess.run(command, check=True, timeout=60)
            subprocess.run([str(path / "test")], check=True, timeout=10)

    def test_parsers_control_flow_and_native_payload(self):
        self.compile_and_run(FLOW, [NATIVE / "selinuxpolicy/avc_lookup_probe.cpp",
                                   NATIVE / "selinuxpolicy/avc_lookup_native_bridge.cpp"])

    def test_io_adapter_transactions_and_reads(self):
        self.compile_and_run(IO, [])


if __name__ == "__main__":
    unittest.main()

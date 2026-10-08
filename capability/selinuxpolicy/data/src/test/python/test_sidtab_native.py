#!/usr/bin/env python3
# Copyright (C) 2026 Duck Apps Contributor
# If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Host regression tests for native SID-table control flow and parsing, not device validation."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[6]
NATIVE = ROOT / "capability/selinuxpolicy/data/src/main/cpp"
COMMON = ROOT / "core/native/src/main/cpp"

PARSER_TEST = r'''
#include "selinuxpolicy/sidtab_probe_io.h"
#include <cassert>
#include <climits>
#include <cstring>
using duckdetector::selinux::sidtab::parse_entries;
int main() {
    int64_t count = -1;
    const char *good[] = {"entries: 0\nbuckets used: 0/256\n", "entries: 2147483647\n", "entries: 123\n"};
    for (const auto text : good) assert(parse_entries(text, strlen(text), count));
    const char *bad[] = {"", "entries: -1\n", "entries: 1", "entries: 1x\n", "entries: \n",
        "entries: 2147483648\n", "entries: 99999999999999999999\n", "entries: 1\nentries: 2\n", "xentries: 1\n"};
    for (const auto text : bad) assert(!parse_entries(text, strlen(text), count));
    const char text[] = "entries: 12\n";
    for (size_t i = 0; i < strlen(text); ++i) assert(!parse_entries(text, i, count));
}
'''

FLOW_TEST = r'''
#include "selinuxpolicy/sidtab_probe.h"
#include "selinuxpolicy/sidtab_probe_io.h"
#include "common/disposable_child.h"
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <unistd.h>

static std::string mode;
static std::set<std::string> registered;
static int reads;
extern "C" uid_t getuid()
#if defined(__linux__)
noexcept
#endif
{ return mode == "wrong_uid" ? 501 : 10000; }

namespace duckdetector::selinux::sidtab {
IoResult read_context(char *buffer, size_t) {
    strcpy(buffer, mode == "wrong_domain" ? "u:r:isolated_app:s0" : "u:r:app_zygote:s0");
    return {0, true};
}
IoResult read_entries(int64_t &value) {
    ++reads;
    if (mode == "stats_denied") return {EACCES, false};
    value = 100 + registered.size();
    return {0, true};
}
State error_state(int error) {
    return error == EACCES || error == EPERM ? State::kPermissionLimited :
        (error ? State::kUnavailable : State::kInconclusive);
}
IoResult check_context(const char *context, bool &canonical) {
    canonical = false;
    if (strcmp(context, "duckdetector-invalid-context") == 0) return {EINVAL, false};
    if (mode == "canonical" && strcmp(context, "u:r:app_zygote:s0") != 0) return {0, false};
    if (mode == "invalid_candidate" && strcmp(context, "u:r:app_zygote:s0") != 0) return {EINVAL, false};
    if (mode != "hidden") registered.insert(context);
    canonical = true;
    return {0, true};
}
IoResult write_current(const char *context) {
    if (mode == "attr_open_denied") return {EACCES, false, false};
    if (mode == "identity") return {0, true, true};
    registered.insert(context);
    return {EACCES, false, true};
}
}

namespace duckdetector::common::detail {
ChildOutcome run_disposable_child(std::span<unsigned char> report, ChildDeadlines,
                                 ChildBody body, const void *context) {
    // A synchronous injected runner tests report framing/control flow; it does not simulate fork safety.
    FILE *file = tmpfile();
    assert(file);
    const int exit_status = body(context, fileno(file));
    const long length = lseek(fileno(file), 0, SEEK_CUR);
    assert(length >= 0 && static_cast<size_t>(length) <= report.size());
    lseek(fileno(file), 0, SEEK_SET);
    assert(read(fileno(file), report.data(), length) == length);
    fclose(file);
    return {.end = mode == "timeout" ? ChildEnd::kTimedOut : ChildEnd::kExited,
        .exit_status = exit_status, .report_length = mode == "truncated" ? 1u : static_cast<size_t>(length)};
}
}

int main() {
    using namespace duckdetector::selinux::sidtab;
    for (const char *test : {"stock", "hidden", "synchronized", "stats_denied", "wrong_domain", "wrong_uid",
                            "identity", "attr_open_denied", "canonical", "invalid_candidate", "timeout", "truncated"}) {
        mode = test;
        registered = {"u:r:app_zygote:s0"};
        reads = 0;
        const auto value = collect();
        if (mode == "stock" || mode == "synchronized" || mode == "hidden") {
            assert(value.report.state == State::kComplete);
            assert(value.report.completed_rounds == 2);
            std::set<std::string> candidates;
            for (const auto &round : value.report.rounds) {
                assert(round.before == round.before_controls);
                assert(round.idle_end == round.after_repeat && round.after_repeat == round.after_attr);
                assert(round.after_context - round.before == (mode == "hidden" ? 0 : 4));
                assert(round.after_attr - round.after_context == (mode == "hidden" ? 4 : 0));
                for (const auto &sample : round.samples) {
                    candidates.insert(sample.context);
                    assert(sample.context_error == 0 && sample.attr_error == EACCES && sample.repeat_error == 0);
                }
            }
            assert(candidates.size() == 8);
            assert(registered.size() == 9); // bounded insertion count, includes the carrier control
        } else if (mode == "stats_denied" || mode == "attr_open_denied") {
            assert(value.report.state == State::kPermissionLimited);
        } else if (mode == "wrong_domain" || mode == "wrong_uid" || mode == "invalid_candidate") {
            assert(value.report.state == State::kUnsupported);
        } else {
            assert(value.report.state == State::kInconclusive);
        }
        if (mode == "identity") assert(value.report.identity_changed && value.report.completed_rounds == 0);
        if (mode == "canonical") assert(value.report.canonical_mismatch);
        if (mode == "wrong_domain" || mode == "wrong_uid") assert(reads == 0);
    }
}
'''


class NativeSidtabTest(unittest.TestCase):
    def compile_and_run(self, harness, sources):
        compiler = os.environ.get("CXX") or shutil.which("clang++") or shutil.which("g++")
        self.assertIsNotNone(compiler, "Host C++20 compiler required")
        with tempfile.TemporaryDirectory(prefix="duck-sidtab-native-") as directory:
            path = Path(directory)
            (path / "test.cpp").write_text(harness)
            command = [compiler, "-std=c++20", "-Wall", "-Wextra", "-Werror", "-I", str(NATIVE), "-I", str(COMMON)]
            if os.uname().sysname == "Darwin":
                # This test exercises control flow, not Android's BOOTTIME clock semantics.
                command += ["-DCLOCK_BOOTTIME=CLOCK_MONOTONIC"]
            command += [str(path / "test.cpp"), *[str(NATIVE / "selinuxpolicy" / source) for source in sources], "-o", str(path / "test")]
            subprocess.run(command, check=True, timeout=60)
            subprocess.run([str(path / "test")], check=True, timeout=10)

    def test_statistics_parser(self):
        self.compile_and_run(PARSER_TEST, ["sidtab_probe_io.cpp"])

    def test_bounded_experiment_control_flow(self):
        self.compile_and_run(FLOW_TEST, ["sidtab_probe.cpp"])


if __name__ == "__main__":
    unittest.main()

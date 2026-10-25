/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "zygisk/common/codec.h"
#include "zygisk/probes/atexit/table.h"

#include <sstream>

#include "common/payload_codec.h"

namespace duckdetector::zygisk {

    namespace {

        const char *group_to_string(const SignalGroup group) {
            switch (group) {
                case SignalGroup::kCrossProcess:
                    return "CROSS_PROCESS";
                case SignalGroup::kRuntime:
                    return "RUNTIME";
                case SignalGroup::kLinker:
                    return "LINKER";
                case SignalGroup::kMaps:
                    return "MAPS";
                case SignalGroup::kHeap:
                    return "HEAP";
                case SignalGroup::kThreads:
                    return "THREADS";
                case SignalGroup::kFd:
                    return "FD";
            }
            return "MAPS";
        }

        const char *severity_to_string(const SignalSeverity severity) {
            switch (severity) {
                case SignalSeverity::kDanger:
                    return "DANGER";
                case SignalSeverity::kWarning:
                    return "WARNING";
            }
            return "WARNING";
        }

    }  // namespace

    std::string escape_value(const std::string &value) {
        return common::escape_payload_value(value);
    }

    std::string encode_snapshot(const Snapshot &snapshot) {
        std::ostringstream output;
        output << "AVAILABLE=" << (snapshot.available ? '1' : '0') << '\n';
        output << "HEAP_AVAILABLE=" << (snapshot.heap_available ? '1' : '0') << '\n';
        output << "TRACER_PID=" << snapshot.tracer_pid << '\n';
        output << "STRONG_HITS=" << snapshot.strong_hits << '\n';
        output << "HEURISTIC_HITS=" << snapshot.heuristic_hits << '\n';
        output << "SOLIST_HITS=" << snapshot.solist_hits << '\n';
        output << "VMAP_HITS=" << snapshot.vmap_hits << '\n';
        output << "ATEXIT_HITS=" << snapshot.atexit_hits << '\n';
        output << "ATEXIT_TABLE_STATE=" << atexit::state_name(snapshot.atexit_table.state) << '\n';
        output << "ATEXIT_TABLE_DUMPABLE=" << snapshot.atexit_table.dumpable << '\n';
        output << "ATEXIT_TABLE_ENTRIES=" << snapshot.atexit_table.entries << '\n';
        output << "ATEXIT_TABLE_NULLS=" << snapshot.atexit_table.null_entries << '\n';
        output << "ATEXIT_TABLE_GAPS=" << snapshot.atexit_table.anchored_gaps << '\n';
        output << "ATEXIT_TABLE_CALLBACKS=" << snapshot.atexit_table.anonymous_callbacks << '\n';
        output << "ATEXIT_TABLE_DETAIL=" << escape_value(snapshot.atexit_table.detail) << '\n';
        output << "SMAPS_HITS=" << snapshot.smaps_hits << '\n';
        output << "NAMESPACE_HITS=" << snapshot.namespace_hits << '\n';
        output << "LINKER_HOOK_HITS=" << snapshot.linker_hook_hits << '\n';
        output << "HEAP_HITS=" << snapshot.heap_hits << '\n';
        output << "THREAD_HITS=" << snapshot.thread_hits << '\n';
        output << "FD_HITS=" << snapshot.fd_hits << '\n';
        for (const auto &trace: snapshot.traces) {
            output << "TRACE="
                   << group_to_string(trace.group) << '\t'
                   << severity_to_string(trace.severity) << '\t'
                   << escape_value(trace.label) << '\t'
                   << escape_value(trace.detail) << '\n';
        }
        return output.str();
    }

}  // namespace duckdetector::zygisk

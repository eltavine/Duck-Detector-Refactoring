/*
 * Copyright 2026 Duck Apps Contributor
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

#include "memory/detectors/signal_detector.h"

#include "memory/common/maps_reader.h"

#include <signal.h>

#include <array>
#include <sstream>

namespace duckdetector::memory {
    namespace {

        Finding make_signal_finding(
                const char *label,
                const FindingSeverity severity,
                const std::string &detail
        ) {
            return Finding{
                    .section = "SIGNAL",
                    .category = "SIGNAL",
                    .label = label,
                    .detail = detail,
                    .severity = severity,
            };
        }

        std::string signal_name(const int signum) {
            switch (signum) {
                case SIGTRAP:
                    return "SIGTRAP";
                case SIGBUS:
                    return "SIGBUS";
                case SIGSEGV:
                    return "SIGSEGV";
                case SIGILL:
                    return "SIGILL";
                default:
                    return "SIG?";
            }
        }

    }  // namespace

    SignalSignals detect_signal_anomalies(const std::vector<MapEntry> &maps) {
        SignalSignals signals;
        const std::array<int, 4> watched_signals{SIGTRAP, SIGBUS, SIGSEGV, SIGILL};

        for (const int signum: watched_signals) {
            struct sigaction action{};
            if (::sigaction(signum, nullptr, &action) != 0) {
                continue;
            }

            std::uintptr_t handler = 0;
            if ((action.sa_flags & SA_SIGINFO) != 0) {
                handler = reinterpret_cast<std::uintptr_t>(action.sa_sigaction);
            } else {
                handler = reinterpret_cast<std::uintptr_t>(action.sa_handler);
            }
            if (handler == 0 ||
                handler == reinterpret_cast<std::uintptr_t>(SIG_DFL) ||
                handler == reinterpret_cast<std::uintptr_t>(SIG_IGN)) {
                continue;
            }

            const auto entry = find_entry_for_address(maps, handler);
            const std::string path = entry ? entry->path : "[unmapped]";
            const std::string lowered = to_lower_ascii(path);
            std::ostringstream detail;
            detail << signal_name(signum) << " handler @ 0x" << std::hex << handler << " in "
                   << path;

            if (!entry.has_value() || is_anonymous_path(path)) {
                signals.suspicious_handler = true;
                signals.anonymous_handler = true;
                signals.findings.push_back(
                        make_signal_finding("Anonymous signal handler", FindingSeverity::kHigh,
                                            detail.str())
                );
                continue;
            }

            if (is_suspicious_loader_path(lowered) || lowered.find("frida") != std::string::npos) {
                signals.suspicious_handler = true;
                signals.frida_named_handler =
                        signals.frida_named_handler || lowered.find("frida") != std::string::npos;
                signals.findings.push_back(
                        make_signal_finding("Suspicious signal handler path",
                                            FindingSeverity::kHigh, detail.str())
                );
            }
        }

        return signals;
    }

}  // namespace duckdetector::memory

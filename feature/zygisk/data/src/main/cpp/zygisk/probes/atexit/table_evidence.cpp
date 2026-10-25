// SPDX-License-Identifier: Apache-2.0
#include "zygisk/probes/atexit/table.h"

namespace duckdetector::zygisk::atexit {
    namespace {
        std::string basename(const std::string &path) {
            const auto slash = path.find_last_of('/');
            return path.substr(slash == std::string::npos ? 0 : slash + 1);
        }

        bool app_image(const std::string &path) {
            return starts_with(path, "/data/app/") || starts_with(path, "/data/user/") ||
                   starts_with(path, "/data/data/") || starts_with(path, "/mnt/expand/");
        }

        std::string dso_path(const Entry &entry, const std::vector<MapEntry> &maps) {
            const auto *owner = find_map_for_address(maps, entry.dso);
            return owner == nullptr ? std::string{} : owner->path;
        }

        bool perfetto(const Entry &entry, const std::vector<MapEntry> &maps) {
            const auto *fn = find_map_for_address(maps, entry.function);
            return fn != nullptr && fn->executable() && basename(fn->path) == "libart.so" &&
                   basename(dso_path(entry, maps)) == "libperfetto_hprof.so";
        }

        bool anonymous_owner(const MapEntry &map) {
            return starts_with(map.path, "/memfd:") || starts_with(map.path, "memfd:") ||
                   map.path == "[anon:]" || map.path == "/dev/zero (deleted)";
        }
    }

    const char *state_name(const TableState state) {
        switch (state) {
            case TableState::kNotCollected: return "NOT_COLLECTED";
            case TableState::kCollected: return "COLLECTED";
            case TableState::kUnsupported: return "UNSUPPORTED";
            case TableState::kUnavailable: return "UNAVAILABLE";
            case TableState::kPermissionDenied: return "PERMISSION_DENIED";
            case TableState::kBusy: return "BUSY";
            case TableState::kInvalid: return "INVALID";
            case TableState::kPartial: return "PARTIAL";
        }
        return "NOT_COLLECTED";
    }

    Evidence interpret_table(const std::vector<Entry> &entries, const std::vector<MapEntry> &maps) {
        Evidence out;
        size_t boundary = entries.size();
        // Application registrations are legitimate unload/JIT activity, outside the zygote window.
        for (size_t i = 0; i < entries.size(); ++i) {
            if (entries[i].empty()) { ++out.null_entries; continue; }
            if (app_image(dso_path(entries[i], maps))) boundary = std::min(boundary, i);
        }
        for (size_t i = 0; i + 1 < boundary; ++i) {
            if (perfetto(entries[i], maps) && perfetto(entries[i + 1], maps)) {
                boundary = i + 1;
                break;
            }
        }
        // An absent boundary cannot establish which registrations came from zygote.
        out.bounded = boundary < entries.size();
        // A discovery-rule quality cutoff, not a Bionic invariant: extensive finalization removes
        // too much live ordering context. Decline interpretation and retain partial coverage.
        out.dense_clearing = !entries.empty() && out.null_entries * 5 >= entries.size() * 3;
        if (!out.bounded || out.dense_clearing) return out;
        for (size_t i = 0; i < boundary; ++i) {
            const auto &entry = entries[i];
            if (entry.empty()) continue;
            const auto *owner = find_map_for_address(maps, entry.function);
            if (owner == nullptr || !owner->executable()) { ++out.unresolved_callbacks; continue; }
            if (anonymous_owner(*owner)) {
                ++out.anonymous_callbacks;
                if (out.anonymous_callbacks <= 8) out.traces.push_back({
                    SignalGroup::kLinker, SignalSeverity::kWarning,
                    "Anonymous exit-handler callback",
                    "Handler " + std::to_string(i) + " resolves into " + owner->path +
                    " before application registrations. This is heuristic residue, not a framework identity.",
                });
            }
        }
        // Missing mappings are coverage failures; only all-zero entries are known finalization holes.
        for (size_t start = 0; start < boundary;) {
            if (!entries[start].empty()) { ++start; continue; }
            size_t end = start;
            while (end < entries.size() && entries[end].empty()) ++end;
            const size_t count = end - start;
            bool anchored = false;
            if (count >= 3 && start > 0 && end <= boundary && end < entries.size()) {
                const auto previous = basename(dso_path(entries[start - 1], maps));
                anchored = previous == "libadbconnection.so" || previous == "libwilhelm.so";
                if (previous == "libart.so" && start >= 16) {
                    anchored = true;
                    for (size_t i = start - 16; i < start; ++i) {
                        anchored = anchored && !entries[i].empty() && basename(dso_path(entries[i], maps)) == "libart.so";
                    }
                }
                if (end + 1 < entries.size()) anchored = anchored ||
                    (perfetto(entries[end], maps) && perfetto(entries[end + 1], maps));
            }
            if (anchored) {
                ++out.anchored_gaps;
                if (out.anchored_gaps <= 8) out.traces.push_back({
                    SignalGroup::kLinker, SignalSeverity::kWarning,
                    "Exit-handler gap near system runtime",
                    std::to_string(count) + " cleared handlers at indices " + std::to_string(start) + "–" +
                    std::to_string(end - 1) + " precede application registrations and adjoin a runtime anchor. "
                    "Normal DSO finalization can produce the same pattern; review alongside other evidence.",
                });
            }
            start = end;
        }
        return out;
    }
}  // namespace duckdetector::zygisk::atexit

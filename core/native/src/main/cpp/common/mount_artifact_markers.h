// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

namespace duckdetector::common {
    inline bool mount_path_is_within(const std::string &path, const std::string &prefix) {
        return path == prefix || (path.size() > prefix.size() &&
               path.compare(0, prefix.size(), prefix) == 0 && path[prefix.size()] == '/');
    }

    // Match structured path/source fields, never incidental words in options or a filename.
    inline std::vector<std::string> mount_artifact_labels(
            const std::string &root, const std::string &target, std::string source
    ) {
        const auto sourcePath = source;
        std::transform(source.begin(), source.end(), source.begin(), [](unsigned char value) {
            return static_cast<char>(std::tolower(value));
        });
        std::vector<std::string> labels;
        if (source == "magisk") labels.emplace_back("Magisk");
        if (source == "ksu" || source == "kernelsu") labels.emplace_back("KernelSU");
        if (source == "zygisk") labels.emplace_back("Zygisk");
        if (source == "apatch") labels.emplace_back("APatch");
        if (source == "magic_mount") labels.emplace_back("Magic mount");
        for (const auto &path: {root, target, sourcePath}) {
            if (mount_path_is_within(path, "/data/adb")) labels.emplace_back("data/adb");
            if (mount_path_is_within(path, "/adb/modules")) labels.emplace_back("ADB modules");
            if (mount_path_is_within(path, "/.magisk") ||
                mount_path_is_within(path, "/sbin/.magisk") ||
                mount_path_is_within(path, "/dev/.magisk") ||
                mount_path_is_within(path, "/debug_ramdisk/.magisk")) labels.emplace_back("Magisk");
            if (mount_path_is_within(path, "/.magic_mount")) labels.emplace_back("Magic mount");
            if (mount_path_is_within(path, "/debug_ramdisk")) labels.emplace_back("debug_ramdisk");
        }
        std::sort(labels.begin(), labels.end());
        labels.erase(std::unique(labels.begin(), labels.end()), labels.end());
        return labels;
    }
}  // namespace duckdetector::common

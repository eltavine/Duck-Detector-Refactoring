// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <algorithm>
#include <string>
#include <string_view>

namespace duckdetector::package_paths {
    namespace detail {
        inline bool is_install_token(const std::string_view value) {
            // PackageManagerServiceUtils.getNextCodePath encodes 16 random bytes as
            // URL-safe Base64. These tokens identify an installation, not a module.
            return value.size() == 24 && value.substr(22) == "==" &&
                   std::all_of(value.begin(), value.begin() + 22, [](const char ch) {
                       return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                              (ch >= '0' && ch <= '9') || ch == '-' || ch == '_';
                   });
        }

        inline bool is_package_name(const std::string_view value) {
            return !value.empty() &&
                   std::all_of(value.begin(), value.end(), [](const char ch) {
                       return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                              (ch >= '0' && ch <= '9') || ch == '_' || ch == '.';
                   });
        }
    }

    // Only for keyword classification. Keep original paths for reporting, file
    // access and mapping identity. Also accepts ART's [anon:dalvik-<path>] labels.
    inline std::string without_install_tokens(const std::string_view path) {
        auto root = path.find("/data/app/");
        size_t component_start;
        if (root != std::string_view::npos) {
            component_start = root + std::string_view("/data/app/").size();
        } else {
            root = path.find("/mnt/expand/");
            if (root == std::string_view::npos) {
                return std::string(path);
            }
            const auto volume_end = path.find('/', root + std::string_view("/mnt/expand/").size());
            if (volume_end == std::string_view::npos || path.substr(volume_end, 5) != "/app/") {
                return std::string(path);
            }
            component_start = volume_end + 5;
        }

        const auto first_start = component_start;
        auto component_end = path.find('/', component_start);
        if (component_end == std::string_view::npos) {
            return std::string(path);
        }
        const auto first = path.substr(component_start, component_end - component_start);
        if (first.substr(0, 2) == "~~") {
            if (!detail::is_install_token(first.substr(2))) {
                return std::string(path);
            }
            component_start = component_end + 1;
            component_end = path.find('/', component_start);
            if (component_end == std::string_view::npos) {
                return std::string(path);
            }
        }

        const auto package_dir = path.substr(component_start, component_end - component_start);
        if (package_dir.size() <= 25) {
            return std::string(path);
        }
        const auto separator = package_dir.size() - 25;
        const auto package_name = package_dir.substr(0, separator);
        if (package_dir[separator] != '-' || !detail::is_package_name(package_name) ||
            !detail::is_install_token(package_dir.substr(separator + 1))) {
            return std::string(path);
        }

        std::string result(path.substr(0, first_start));
        result.append(package_name);
        result.append(path.substr(component_end));
        return result;
    }
}

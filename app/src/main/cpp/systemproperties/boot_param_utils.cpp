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

#include "systemproperties/boot_param_utils.h"

#include "systemproperties/property_utils.h"

#include <sstream>
#include <string>

namespace systemproperties {

    namespace {

        std::string strip_quotes(std::string value) {
            value = trim_copy(value);
            if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
                value = value.substr(1, value.size() - 2);
            }
            return value;
        }

        bool
        should_keep_key(const std::string &key, const std::set<std::string> &interesting_keys) {
            if (!key.starts_with("androidboot.")) {
                return false;
            }
            return interesting_keys.empty() || interesting_keys.find(key) != interesting_keys.end();
        }

    }  // namespace

    std::map<std::string, std::string> parse_cmdline_params(
            const std::string &raw_cmdline,
            const std::set<std::string> &interesting_keys
    ) {
        std::map<std::string, std::string> params;
        std::istringstream stream(raw_cmdline);
        std::string token;
        while (stream >> token) {
            const size_t delimiter = token.find('=');
            if (delimiter == std::string::npos) {
                continue;
            }
            const std::string key = trim_copy(token.substr(0, delimiter));
            if (!should_keep_key(key, interesting_keys)) {
                continue;
            }
            params[key] = strip_quotes(token.substr(delimiter + 1));
        }
        return params;
    }

    std::map<std::string, std::string> parse_bootconfig_params(
            const std::string &raw_bootconfig,
            const std::set<std::string> &interesting_keys
    ) {
        std::map<std::string, std::string> params;
        std::istringstream stream(raw_bootconfig);
        std::string line;
        while (std::getline(stream, line)) {
            const std::string trimmed = trim_copy(line);
            if (trimmed.empty()) {
                continue;
            }
            const size_t delimiter = trimmed.find('=');
            if (delimiter == std::string::npos) {
                continue;
            }
            const std::string key = trim_copy(trimmed.substr(0, delimiter));
            if (!should_keep_key(key, interesting_keys)) {
                continue;
            }
            params[key] = strip_quotes(trimmed.substr(delimiter + 1));
        }
        return params;
    }

}  // namespace systemproperties

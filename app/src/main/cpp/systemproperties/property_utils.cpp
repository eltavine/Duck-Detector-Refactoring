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

#include "systemproperties/property_utils.h"

#include <algorithm>
#include <cctype>
#include <fcntl.h>
#include <string>
#include <sys/system_properties.h>
#include <unistd.h>

namespace systemproperties {

    namespace {

        struct PropertyReadContext {
            std::string value;
        };

        void property_read_callback(
                void *cookie,
                const char *,
                const char *value,
                uint32_t
        ) {
            auto *context = static_cast<PropertyReadContext *>(cookie);
            if (context == nullptr) {
                return;
            }
            context->value = value != nullptr ? value : "";
        }

    }  // namespace

    std::string trim_copy(const std::string &value) {
        const auto begin = std::find_if_not(value.begin(), value.end(), [](unsigned char ch) {
            return std::isspace(ch) != 0;
        });
        const auto end = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char ch) {
            return std::isspace(ch) != 0;
        }).base();
        if (begin >= end) {
            return "";
        }
        return std::string(begin, end);
    }

    std::string escape_value(std::string value) {
        for (char &ch: value) {
            if (ch == '\0') {
                ch = ' ';
            }
        }

        std::string escaped;
        escaped.reserve(value.size());
        for (char ch: value) {
            switch (ch) {
                case '\n':
                    escaped += "\\n";
                    break;
                case '\r':
                    escaped += "\\r";
                    break;
                default:
                    escaped += ch;
                    break;
            }
        }
        return escaped;
    }

    std::string read_text_file(const char *path, size_t max_bytes) {
        const int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            return "";
        }

        std::string content;
        content.reserve(4096);
        char buffer[4096];
        ssize_t bytes_read = 0;
        while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
            content.append(buffer, static_cast<size_t>(bytes_read));
            if (content.size() >= max_bytes) {
                break;
            }
        }
        close(fd);

        while (!content.empty() &&
               (content.back() == '\n' || content.back() == '\r' || content.back() == '\0')) {
            content.pop_back();
        }
        return content;
    }

    std::string read_system_property(const std::string &key) {
        const prop_info *info = __system_property_find(key.c_str());
        if (info == nullptr) {
            return "";
        }

        PropertyReadContext context;
        __system_property_read_callback(
                info,
                property_read_callback,
                &context
        );
        return context.value;
    }

    std::map<std::string, std::string>
    read_system_properties(const std::vector<std::string> &keys) {
        std::map<std::string, std::string> properties;
        for (const std::string &key: keys) {
            properties[key] = read_system_property(key);
        }
        return properties;
    }

}  // namespace systemproperties

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

#include "playintegrityfix/probes/property_probe.h"

#include <sys/system_properties.h>

namespace duckdetector::playintegrityfix {

    std::map<std::string, std::string> read_properties(const std::vector<std::string> &keys) {
        std::map<std::string, std::string> properties;
        for (const std::string &key: keys) {
            char buffer[PROP_VALUE_MAX] = {};
            const int length = __system_property_get(key.c_str(), buffer);
            if (length > 0) {
                properties[key] = std::string(buffer, static_cast<size_t>(length));
            } else {
                properties[key] = "";
            }
        }
        return properties;
    }

}  // namespace duckdetector::playintegrityfix

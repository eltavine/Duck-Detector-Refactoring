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

#ifndef DUCKDETECTOR_MEMORY_COMMON_MAPS_READER_H
#define DUCKDETECTOR_MEMORY_COMMON_MAPS_READER_H

#include "memory/common/types.h"

#include <optional>
#include <string>
#include <vector>

namespace duckdetector::memory {

    std::vector<MapEntry> read_self_maps();

    std::vector<SmapsEntry> read_self_smaps();

    std::optional<MapEntry> find_entry_for_address(
            const std::vector<MapEntry> &maps,
            std::uintptr_t address
    );

    bool is_system_path(const std::string &path);

    bool is_benign_art_code_cache_path(const std::string &path);

    bool is_probably_jit_path(const std::string &path);

    bool is_suspicious_loader_path(const std::string &path);

    bool is_benign_loader_artifact_path(const std::string &path);

    bool is_anonymous_path(const std::string &path);

    std::string basename_of(const std::string &path);

    std::string to_lower_ascii(std::string value);

}  // namespace duckdetector::memory

#endif  // DUCKDETECTOR_MEMORY_COMMON_MAPS_READER_H

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

#ifndef DUCKDETECTOR_SELINUX_SIDTAB_PROBE_IO_H
#define DUCKDETECTOR_SELINUX_SIDTAB_PROBE_IO_H

#include "selinuxpolicy/sidtab_probe.h"
#include <cstddef>

namespace duckdetector::selinux::sidtab {
    struct IoResult { int error = 0; bool complete = false; bool submitted = false; };
    IoResult read_context(char *buffer, std::size_t capacity);
    IoResult read_entries(int64_t &entries);
    IoResult check_context(const char *context, bool &canonical_match);
    IoResult write_current(const char *context);
    bool parse_entries(const char *buffer, std::size_t length, int64_t &entries);
} // namespace duckdetector::selinux::sidtab
#endif

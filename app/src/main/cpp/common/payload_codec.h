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

#ifndef DUCKDETECTOR_COMMON_PAYLOAD_CODEC_H
#define DUCKDETECTOR_COMMON_PAYLOAD_CODEC_H

#include <string>
#include <string_view>

namespace duckdetector::common {

    // Canonical escaping for the newline-separated `KEY=value` payloads every snapshot bridge
    // hands to Kotlin. Multi-column records join their columns with tabs, so a value may never
    // contain a raw backslash, newline, carriage return, or tab:
    //
    //   '\\' -> "\\\\"   LF -> "\\n"   CR -> "\\r"   TAB -> "\\t"
    //
    // Each module used to carry its own copy of this switch and they had drifted apart: some
    // omitted the backslash case, which makes the escaping ambiguous and lets the Kotlin decoder
    // reconstruct a value that was never sent. The inverse is NativePayloadCodec.decodeValue in
    // core/native, and NativePayloadCodecTest pins the pair.
    std::string escape_payload_value(std::string_view value);

}  // namespace duckdetector::common

#endif  // DUCKDETECTOR_COMMON_PAYLOAD_CODEC_H

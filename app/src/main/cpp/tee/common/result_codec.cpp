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

#include "tee/common/result_codec.h"

namespace ducktee::common {

    void ResultCodec::put(std::string_view key, std::string_view value) {
        buffer_.append(key);
        buffer_.push_back('=');
        buffer_.append(value);
        buffer_.push_back('\n');
    }

    void ResultCodec::put_bool(std::string_view key, bool value) {
        put(key, value ? "1" : "0");
    }

    void ResultCodec::put_int(std::string_view key, long value) {
        put(key, std::to_string(value));
    }

    void ResultCodec::put_many(std::string_view key, const std::vector<std::string> &values) {
        for (const auto &value: values) {
            put(key, value);
        }
    }

    std::string ResultCodec::str() const {
        return buffer_;
    }

}  // namespace ducktee::common

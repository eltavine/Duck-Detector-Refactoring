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

#ifndef DUCKDETECTOR_TEE_COMMON_RESULT_CODEC_H
#define DUCKDETECTOR_TEE_COMMON_RESULT_CODEC_H

#include <string>
#include <string_view>
#include <vector>

namespace ducktee::common {

    class ResultCodec {
    public:
        void put(std::string_view key, std::string_view value);

        void put_bool(std::string_view key, bool value);

        void put_int(std::string_view key, long value);

        void put_many(std::string_view key, const std::vector<std::string> &values);

        [[nodiscard]] std::string str() const;

    private:
        std::string buffer_;
    };

}  // namespace ducktee::common

#endif  // DUCKDETECTOR_TEE_COMMON_RESULT_CODEC_H

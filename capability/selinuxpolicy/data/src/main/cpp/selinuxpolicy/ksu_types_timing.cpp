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

#include "selinuxpolicy/context_validity_internal.h"
#include "selinuxpolicy/raw_context_node.h"

#include <algorithm>
#include <array>
#include <memory>
#include <new>
#include <numeric>
#include <optional>
#include <sched.h>

namespace {

    constexpr int kBatchCount = 9;
    constexpr int kQueriesPerBatch = 1'500;
    constexpr int kWarmupPairs = 32;
    using PairDifferences = std::array<jlong, kBatchCount * kQueriesPerBatch>;
    using duckdetector::selinux::query_raw_context_node;

    struct TimingSamples {
        std::array<jlong, kBatchCount> batch_differences{};
        std::array<jlong, 2 * kBatchCount> batch_direction_counts{};
        jlong median_pair_ns = 0;
    };

    class ScopedCpuAffinity {
    public:
        explicit ScopedCpuAffinity(int cpu) {
            if (sched_getaffinity(0, sizeof(original_), &original_) != 0) return;
            cpu_set_t requested;
            CPU_ZERO(&requested);
            CPU_SET(cpu, &requested);
            pinned_ = sched_setaffinity(0, sizeof(requested), &requested) == 0;
        }

        ~ScopedCpuAffinity() {
            if (pinned_) sched_setaffinity(0, sizeof(original_), &original_);
        }

    private:
        cpu_set_t original_{};
        bool pinned_ = false;
    };

    bool collect_pairs(
            const char *ksu,
            const char *invalid,
            PairDifferences &differences
    ) {
        const ScopedCpuAffinity affinity(0);
        for (int batch = 0; batch < kBatchCount; ++batch) {
            const int first_pair = batch == 0 ? -kWarmupPairs : 0;
            const int offset = batch * kQueriesPerBatch;
            for (int pair = first_pair; pair < kQueriesPerBatch; ++pair) {
                const auto a = query_raw_context_node(ksu, true);
                const auto b = query_raw_context_node(invalid, true);
                if (!a.elapsed_ns || !b.elapsed_ns ||
                    !(a.complete || a.rejected()) || !b.rejected()) {
                    return false;
                }
                if (pair >= 0) {
                    differences[offset + pair] = *a.elapsed_ns - *b.elapsed_ns;
                }
            }
        }
        return true;
    }

    std::optional<TimingSamples> measure_batches(const char *ksu, const char *invalid) {
        const std::unique_ptr<PairDifferences> samples(new (std::nothrow) PairDifferences{});
        if (!samples) return std::nullopt;
        auto &differences = *samples;
        if (!collect_pairs(ksu, invalid, differences)) return std::nullopt;

        TimingSamples result;
        for (int batch = 0; batch < kBatchCount; ++batch) {
            const auto first = differences.begin() + batch * kQueriesPerBatch;
            for (auto pair = first; pair != first + kQueriesPerBatch; ++pair) {
                result.batch_differences[batch] += *pair;
                result.batch_direction_counts[2 * batch] += *pair > 0;
                result.batch_direction_counts[2 * batch + 1] += *pair < 0;
            }
        }
        const auto middle = differences.begin() + differences.size() / 2;
        std::nth_element(differences.begin(), middle, differences.end());
        result.median_pair_ns = std::midpoint(*std::max_element(differences.begin(), middle), *middle);
        return result;
    }

}  // namespace

extern "C" JNIEXPORT jlongArray JNICALL
Java_com_eltavine_duckdetector_capability_selinuxpolicy_data_SelinuxRawAccess_nativeMeasureKsuContextTiming(
        JNIEnv *env, jobject
) {
    using namespace duckdetector::selinux::detail;
    const auto carrier = read_process_context();
    if (context_type(carrier) != kExpectedCarrierType) {
        return nullptr;
    }

    const auto control = query_raw_context_node(carrier.c_str(), true);
    if (!control.complete || !control.elapsed_ns) {
        return nullptr;
    }
    const auto samples = measure_batches(kKsuContext, "u:r:duck_detector_invalid:s0");
    if (!samples) {
        return nullptr;
    }

    constexpr int kCountOffset = kBatchCount + 1;
    constexpr int kPairCountIndex = kCountOffset + 2 * kBatchCount;
    jlongArray result = env->NewLongArray(kPairCountIndex + 1);
    if (result != nullptr) {
        env->SetLongArrayRegion(result, 0, kBatchCount, samples->batch_differences.data());
        env->SetLongArrayRegion(result, kBatchCount, 1, &samples->median_pair_ns);
        env->SetLongArrayRegion(result, kCountOffset, 2 * kBatchCount, samples->batch_direction_counts.data());
        const jlong pairs_per_batch = kQueriesPerBatch;
        env->SetLongArrayRegion(result, kPairCountIndex, 1, &pairs_per_batch);
    }
    return result;
}

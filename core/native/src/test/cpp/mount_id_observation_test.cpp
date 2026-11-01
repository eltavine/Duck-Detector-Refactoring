// SPDX-License-Identifier: Apache-2.0
#include "common/mount_id_observation.h"

#include <cassert>
#include <climits>
#include <string>
#include <vector>

struct Entry {
    int id;
    std::string target;
};

using duckdetector::common::observe_mount_id_discontinuities;

int main() {
    // Synthetic mount lists exercise allocator/namespace semantics, not a stock-device baseline.
    for (const int skipped: {1, 2, 3, 8, 16}) {
        for (const bool art: {false, true}) {
            const std::vector<Entry> entries = art
                    ? std::vector<Entry>{{100, "/apex/com.android.art"}, {101 + skipped, "/apex/other"}}
                    : std::vector<Entry>{{100, "/data/user/0"}, {101 + skipped, "/data_mirror"}};
            const auto observations = observe_mount_id_discontinuities(entries);
            assert(observations.size() == 1);
            assert(observations[0].previousId == 100);
            assert(observations[0].currentId == 101 + skipped);
            const auto detail = observations[0].detail();
            assert(detail.find("ID 100") != std::string::npos);
            assert(detail.find("ID " + std::to_string(101 + skipped)) != std::string::npos);
            assert(detail.find("need not be consecutive") != std::string::npos);
            assert(detail.find("Missing") == std::string::npos);
            assert(detail.find("Expected") == std::string::npos);
        }
    }
    // A numerically intermediate ID is visible elsewhere: adjacent records cannot count
    // IDs absent from the namespace. Descending/reused IDs are valid observations too.
    const std::vector<Entry> reordered = {
            {105, "/other"}, {100, "/apex/com.android.art"}, {109, "/data_mirror"},
    };
    assert(observe_mount_id_discontinuities(reordered).size() == 1);
    const std::vector<Entry> descending = {{200, "/data/user"}, {12, "/data_mirror"}};
    assert(observe_mount_id_discontinuities(descending)[0].currentId == 12);
    const std::vector<Entry> large = {{INT_MAX, "/apex/com.android.art"}, {1, "/data_mirror"}};
    assert(observe_mount_id_discontinuities(large).size() == 1);
    const std::vector<Entry> consecutive = {{100, "/apex/com.android.art"}, {101, "/data_mirror"}};
    assert(observe_mount_id_discontinuities(consecutive).empty());
    assert(observe_mount_id_discontinuities(std::vector<Entry>{}).empty());
    assert(observe_mount_id_discontinuities(std::vector<Entry>{{100, "/data_mirror"}}).empty());
    assert(observe_mount_id_discontinuities(std::vector<Entry>{{100, "/apex/com.android.art"}}).empty());
    assert(observe_mount_id_discontinuities(std::vector<Entry>{{1, "/x"}, {900, "/y"}}).empty());
    assert(observe_mount_id_discontinuities(std::vector<Entry>{{0, "/x"}, {9, "/data_mirror"}}).empty());
}

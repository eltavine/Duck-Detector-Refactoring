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

#ifndef DUCKDETECTOR_NATIVEROOT_PROBES_SUSFS_GETDENTS_RACE_PROBE_H
#define DUCKDETECTOR_NATIVEROOT_PROBES_SUSFS_GETDENTS_RACE_PROBE_H

#include "nativeroot/common/types.h"

namespace duckdetector::nativeroot {

    // Outcome of the getdents64 buffer race, carried in ProbeResult::numeric_value.
    enum class SusfsGetdentsRaceOutcome : long {
        kNotObserved = 0,  // fork/pipe failure, or the probe child crashed
        kLeaked = 1,        // hidden "susfs"/"guard_lkm" names recovered from the buffer
        kRanClean = 2,     // race ran to completion without recovering hidden names
    };

    ProbeResult run_susfs_getdents_race_probe();

}  // namespace duckdetector::nativeroot

#endif  // DUCKDETECTOR_NATIVEROOT_PROBES_SUSFS_GETDENTS_RACE_PROBE_H

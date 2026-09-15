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

#ifndef DUCKDETECTOR_NATIVEROOT_PROBES_KERNELPATCH_SUPERKEY_PROBE_H
#define DUCKDETECTOR_NATIVEROOT_PROBES_KERNELPATCH_SUPERKEY_PROBE_H

#include "nativeroot/common/types.h"

namespace duckdetector::nativeroot {

    // Set in ProbeResult::aux_flags when the run produced at least one
    // trustworthy residency measurement. It is kept separate from
    // checked_count so that an unusable run (no control page, control page
    // resident, mincore error) is reported as unavailable rather than clean.
    constexpr long kSuperkeyAuxUsable = 1L << 0;

    ProbeResult run_kernelpatch_superkey_check();

}  // namespace duckdetector::nativeroot

#endif  // #ifdef DUCKDETECTOR_NATIVEROOT_PROBES_KERNELPATCH_SUPERKEY_PROBE_H

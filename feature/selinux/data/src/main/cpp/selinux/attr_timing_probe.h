/*
 * Copyright 2026 Duck Apps Contributor
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
#ifndef DUCKDETECTOR_SELINUX_ATTR_TIMING_PROBE_H
#define DUCKDETECTOR_SELINUX_ATTR_TIMING_PROBE_H

#include <string>

namespace duckdetector::selinux {
    // Ordinary-app, read-only diagnostic outcome: writes are required to fail
    // with EACCES; the implementation aborts on any unexpected return value.
    std::string collect_attr_timing_probe();
}

#endif

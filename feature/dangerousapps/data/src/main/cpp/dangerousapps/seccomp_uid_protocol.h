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

#pragma once
#include <cstdint>
#include <linux/audit.h>

namespace duckdetector::dangerousapps::seccomp_uid {
constexpr int kMaxSpan = 10000;
constexpr int kVersion = 1;

// install_status, mirrored by HmaSeccompUidBridge.
constexpr int kInstalled = 0;
constexpr int kForeignListener = 1;
constexpr int kUnsupported = 2;
constexpr int kRestricted = 3;
constexpr int kFailure = 4;
constexpr int kInstallTrapped = 5;

// query_outcome, mirrored by HmaSeccompUidBridge.
constexpr int kQueryComplete = 0;
constexpr int kQueryTrapped = 1;
constexpr int kQuerySignaled = 2;
constexpr int kQueryTimeout = 3;
constexpr int kQueryFailure = 4;
constexpr int kQueryNotRun = 5;


struct Result {
    int version;
    int install_status;
    int install_error;
    int kernel_major;
    int kernel_minor;
    int queried;
    int notified;
    int first_suppressed;
    int last_suppressed;
    int query_outcome;
    int query_error;
    int self_notified;
};


#if defined(__aarch64__)
constexpr uint32_t kAuditArch = AUDIT_ARCH_AARCH64;
#elif defined(__arm__)
constexpr uint32_t kAuditArch = AUDIT_ARCH_ARM;
#elif defined(__x86_64__)
constexpr uint32_t kAuditArch = AUDIT_ARCH_X86_64;
#elif defined(__i386__)
constexpr uint32_t kAuditArch = AUDIT_ARCH_I386;
#else
constexpr uint32_t kAuditArch = 0;
#endif
constexpr int kQueryTrapExit = 126;

void service_queries(int listener_fd, int report_fd, int first_uid, int last_uid, Result &result);
bool valid_result(const Result &result, int first_uid, int last_uid);
Result run_probe(int first_uid, int last_uid);
} // namespace duckdetector::dangerousapps::seccomp_uid

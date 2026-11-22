// SPDX-License-Identifier: Apache-2.0
#include "selinuxpolicy/raw_context_node.h"

#include "common/arm64_counter.h"
#include "selinuxpolicy/context_validity_internal.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <unistd.h>

namespace duckdetector::selinux {

    bool RawContextNodeResult::rejected() const {
        return open_error == 0 && write_error == EINVAL;
    }

    RawContextNodeResult query_raw_context_node(const char *context, bool measure_write) {
        RawContextNodeResult result;
        const auto size = std::strlen(context);
        // Both callers use DirtySepolicy's write-only selinuxfs context transaction.
        const int fd = open(detail::kSelinuxContextPath, O_WRONLY | O_CLOEXEC);
        if (fd < 0) {
            result.open_error = errno;
            return result;
        }

        std::uint64_t begin = 0;
        std::uint64_t end = 0;
        if (measure_write && !common::arm64_counter::read_time_ns(&begin)) {
            close(fd);
            return result;
        }
        const auto written = write(fd, context, size);
        const int saved_errno = errno;
        if (measure_write && common::arm64_counter::read_time_ns(&end) && end >= begin) {
            result.elapsed_ns = static_cast<std::int64_t>(end - begin);
        }
        close(fd);
        result.complete = written == static_cast<ssize_t>(size);
        result.write_error = written < 0 ? saved_errno : 0;
        return result;
    }

}  // namespace duckdetector::selinux

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_capability_selinuxpolicy_data_SelinuxRawAccess_nativeContextNode(
        JNIEnv *env,
        jobject,
        jstring context
) {
    const char *value = env->GetStringUTFChars(context, nullptr);
    if (value == nullptr) return nullptr;
    const auto result = duckdetector::selinux::query_raw_context_node(value, false);
    env->ReleaseStringUTFChars(context, value);

    std::string status;
    if (result.open_error != 0) {
        status = "UNAVAILABLE:open errno=" + std::to_string(result.open_error);
    } else if (result.complete) {
        status = "VALID";
    } else if (result.rejected()) {
        status = "INVALID";
    } else if (result.write_error != 0) {
        status = "UNAVAILABLE:write errno=" + std::to_string(result.write_error);
    } else {
        status = "UNAVAILABLE:write short_write";
    }
    return env->NewStringUTF(status.c_str());
}

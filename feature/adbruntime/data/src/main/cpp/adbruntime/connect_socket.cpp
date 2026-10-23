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

#include <jni.h>

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace {

// AF_UNIX address for an abstract name ("\0name") or a filesystem path. Abstract sockets are
// looked up by name *and* socket type, so a mismatch would read as "no listener".
bool build_address(const char *name, const size_t length, const bool abstract_name,
                   sockaddr_un &address, socklen_t &address_length) {
    if (length == 0) {
        return false;
    }
    std::memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    const size_t offset = offsetof(sockaddr_un, sun_path);
    if (abstract_name) {
        if (length > sizeof(address.sun_path) - 1) {
            return false;
        }
        address.sun_path[0] = '\0';
        std::memcpy(address.sun_path + 1, name, length);
        address_length = static_cast<socklen_t>(offset + 1 + length);
        return true;
    }
    if (length >= sizeof(address.sun_path)) {
        return false;
    }
    std::memcpy(address.sun_path, name, length);
    address.sun_path[length] = '\0';
    address_length = static_cast<socklen_t>(offset + length + 1);
    return true;
}

// One nonblocking connect() and one close(); no protocol bytes are sent. A matching listener can
// return EACCES from SELinux; a missing listener returns ECONNREFUSED. A full listen backlog can
// return EAGAIN rather than blocking the scan, and callers classify it as unavailable.
jint connect_error(const char *name, const size_t length, const bool abstract_name) {
    sockaddr_un address{};
    socklen_t address_length = 0;
    if (!build_address(name, length, abstract_name, address, address_length)) {
        return EINVAL;
    }
    const int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        return errno;
    }
    // Do not retry EINTR: the connection may have started, and repeated retries can
    // defeat the scan's cancellation boundary. Unknown errno values stay unavailable.
    const int result = connect(fd, reinterpret_cast<const sockaddr *>(&address), address_length);
    const int error = result == 0 ? 0 : errno;
    close(fd);
    return error;
}
}  // namespace

extern "C" JNIEXPORT jint JNICALL
Java_com_eltavine_duckdetector_features_adbruntime_data_repository_AdbJdwpSocketBridge_nativeConnectErrno(
        JNIEnv *env, jobject, jstring name, jboolean abstract_name) {
    if (name == nullptr) {
        return EINVAL;
    }
    const char *chars = env->GetStringUTFChars(name, nullptr);
    if (chars == nullptr) {
        return EINVAL;
    }
    const size_t length = std::strlen(chars);
    const jint result = connect_error(chars, length, abstract_name != JNI_FALSE);
    env->ReleaseStringUTFChars(name, chars);
    return result;
}

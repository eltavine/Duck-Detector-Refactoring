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

#include <jni.h>

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <fcntl.h>
#include <string>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

#include <dirent.h>

namespace {

    constexpr char kSelfContextPath[] = "/proc/self/attr/current";
    constexpr char kProcDirPath[] = "/proc";

    constexpr const char *kSuspiciousTokens[] = {
            "magisk",
            "apatch",
            "kernelsu",
            ":su:",
            "permissive",
    };

    constexpr const char *kNormalTokens[] = {
            "untrusted_app",
            "platform_app",
            "system_app",
            "priv_app",
    };

    struct linux_dirent64 {
        std::uint64_t d_ino;
        std::int64_t d_off;
        unsigned short d_reclen;
        unsigned char d_type;
        char d_name[];
    };

    int syscall_openat_readonly(const char *path, int flags = O_RDONLY | O_CLOEXEC) {
        return static_cast<int>(syscall(__NR_openat, AT_FDCWD, path, flags));
    }

    ssize_t syscall_read_fd(int fd, void *buffer, size_t count) {
        return syscall(__NR_read, fd, buffer, count);
    }

    int syscall_close_fd(int fd) {
        return static_cast<int>(syscall(__NR_close, fd));
    }

    int syscall_getdents64_fd(int fd, void *buffer, size_t count) {
#if defined(__NR_getdents64)
        return static_cast<int>(syscall(__NR_getdents64, fd, buffer, count));
#else
        (void)fd;
        (void)buffer;
        (void)count;
        return -1;
#endif
    }

    std::string trim_copy(std::string value) {
        for (size_t index = 0; index < value.size(); ++index) {
            if (value[index] == '\0' || value[index] == '\r' || value[index] == '\n') {
                value.erase(index);
                break;
            }
        }

        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())) != 0) {
            value.erase(value.begin());
        }
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0) {
            value.pop_back();
        }
        return value;
    }

    std::string lowercase_copy(std::string value) {
        for (char &ch: value) {
            ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        }
        return value;
    }

    bool
    contains_any_token(const std::string &value, const char *const *tokens, size_t token_count) {
        const std::string lower = lowercase_copy(value);
        for (size_t index = 0; index < token_count; ++index) {
            if (lower.find(tokens[index]) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    bool is_suspicious_context(const std::string &context) {
        return !context.empty() && contains_any_token(
                context,
                kSuspiciousTokens,
                sizeof(kSuspiciousTokens) / sizeof(kSuspiciousTokens[0])
        );
    }

    bool is_normal_context(const std::string &context) {
        return !context.empty() && contains_any_token(
                context,
                kNormalTokens,
                sizeof(kNormalTokens) / sizeof(kNormalTokens[0])
        );
    }

    bool is_abnormal_context(const std::string &context) {
        if (context.empty()) {
            return false;
        }
        return is_suspicious_context(context) || !is_normal_context(context);
    }

    bool is_numeric_name(const char *name, size_t max_length) {
        if (name == nullptr || name[0] == '\0') {
            return false;
        }
        for (size_t index = 0; index < max_length && name[index] != '\0'; ++index) {
            if (std::isdigit(static_cast<unsigned char>(name[index])) == 0) {
                return false;
            }
        }
        return true;
    }

    std::string read_file_syscall(const char *path) {
        int fd = syscall_openat_readonly(path);
        if (fd < 0) {
            return "";
        }

        char buffer[512] = {};
        const ssize_t bytes_read = syscall_read_fd(fd, buffer, sizeof(buffer) - 1);
        syscall_close_fd(fd);

        if (bytes_read <= 0) {
            return "";
        }

        return trim_copy(std::string(buffer, static_cast<size_t>(bytes_read)));
    }

    std::string build_snapshot_payload() {
        const std::string self_context = read_file_syscall(kSelfContextPath);
        const bool self_abnormal = is_abnormal_context(self_context);

        std::vector<std::string> suspicious_processes;
        int checked_processes = 0;
        int denied_processes = 0;

        const int proc_fd = syscall_openat_readonly(kProcDirPath,
                                                    O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (proc_fd >= 0) {
            char dent_buffer[4096];
            while (true) {
                const int bytes_read = syscall_getdents64_fd(proc_fd, dent_buffer,
                                                             sizeof(dent_buffer));
                if (bytes_read <= 0) {
                    break;
                }

                int offset = 0;
                while (offset < bytes_read) {
                    if (offset + static_cast<int>(offsetof(linux_dirent64, d_name)) >= bytes_read) {
                        break;
                    }

                    auto *entry = reinterpret_cast<linux_dirent64 *>(dent_buffer + offset);
                    if (entry->d_reclen == 0 || offset + entry->d_reclen > bytes_read) {
                        break;
                    }

                    const size_t max_name_length =
                            entry->d_reclen - offsetof(linux_dirent64, d_name);
                    const bool is_process_dir =
                            (entry->d_type == DT_DIR || entry->d_type == DT_UNKNOWN) &&
                            is_numeric_name(entry->d_name, max_name_length);

                    if (is_process_dir) {
                        char attr_path[256];
                        std::snprintf(attr_path, sizeof(attr_path), "/proc/%s/attr/current",
                                      entry->d_name);
                        const std::string context = read_file_syscall(attr_path);

                        if (!context.empty()) {
                            ++checked_processes;
                            if (is_suspicious_context(context)) {
                                suspicious_processes.emplace_back(
                                        std::string("PID ") + entry->d_name + ": " + context
                                );
                            }
                        } else {
                            ++denied_processes;
                        }
                    }

                    offset += entry->d_reclen;
                }
            }

            syscall_close_fd(proc_fd);
        }

        std::string payload;
        payload.reserve(256 + suspicious_processes.size() * 96);
        payload.append("AVAILABLE=1\n");
        if (!self_context.empty()) {
            payload.append("SELF_CONTEXT=");
            payload.append(self_context);
            payload.push_back('\n');
        }
        payload.append("SELF_ABNORMAL=");
        payload.append(self_abnormal ? "1\n" : "0\n");
        payload.append("PROC_CHECKED=");
        payload.append(std::to_string(checked_processes));
        payload.push_back('\n');
        payload.append("PROC_DENIED=");
        payload.append(std::to_string(denied_processes));
        payload.push_back('\n');
        for (const auto &process: suspicious_processes) {
            payload.append("PROC=");
            payload.append(process);
            payload.push_back('\n');
        }
        return payload;
    }

    jstring to_jstring(JNIEnv *env, const std::string &value) {
        return env->NewStringUTF(value.c_str());
    }

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_su_data_native_SuNativeBridge_nativeCollectSnapshot(
        JNIEnv *env,
        jobject
) {
    return to_jstring(env, build_snapshot_payload());
}

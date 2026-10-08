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

#include "selinuxpolicy/sidtab_probe_io.h"

#include <cerrno>
#include <climits>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

namespace duckdetector::selinux::sidtab {
    namespace {
        constexpr const char *kStats = "/sys/fs/selinux/ss/sidtab_hash_stats";
        constexpr const char *kContext = "/sys/fs/selinux/context";
        constexpr const char *kCurrent = "/proc/self/attr/current";
        constexpr std::size_t kBufferBytes = 512;

        IoResult read_once(const char *path, char *buffer, std::size_t capacity, std::size_t &length) {
            const int fd = open(path, O_RDONLY | O_CLOEXEC);
            if (fd < 0) return {errno, false};
            ssize_t count;
            do { count = read(fd, buffer, capacity - 1); } while (count < 0 && errno == EINTR);
            const int error = count < 0 ? errno : 0;
            close(fd);
            if (count <= 0 || static_cast<std::size_t>(count) >= capacity - 1) return {error, false};
            length = static_cast<std::size_t>(count);
            buffer[length] = 0;
            return {0, true};
        }
    }

    State error_state(const int error) {
        if (error == EACCES || error == EPERM) return State::kPermissionLimited;
        // ENOENT is unavailable: a namespace or path filter may hide a supported interface.
        return error != 0 ? State::kUnavailable : State::kInconclusive;
    }

    // Parse only the full first line. Do not accept prefixes, negative counts, overflow or duplicates.
    // ACK ss/sidtab.c emits "entries: %d\n"; statistics are one RCU traversal, not a locked snapshot.
    bool parse_entries(const char *buffer, const std::size_t length, int64_t &entries) {
        constexpr char prefix[] = "entries: ";
        constexpr std::size_t prefix_length = sizeof(prefix) - 1;
        if (length <= prefix_length || std::memcmp(buffer, prefix, prefix_length) != 0) return false;
        std::size_t index = prefix_length;
        int64_t value = 0;
        const std::size_t start = index;
        while (index < length && buffer[index] >= '0' && buffer[index] <= '9') {
            const int digit = buffer[index++] - '0';
            if (value > (INT_MAX - digit) / 10) return false;
            value = value * 10 + digit;
        }
        if (index == start || index >= length || buffer[index] != '\n') return false;
        for (++index; index + prefix_length <= length; ++index) {
            if (buffer[index - 1] == '\n' && std::memcmp(buffer + index, prefix, prefix_length) == 0) return false;
        }
        entries = value;
        return true;
    }

    IoResult read_entries(int64_t &entries) {
        char buffer[kBufferBytes]{};
        std::size_t length = 0;
        const auto result = read_once(kStats, buffer, sizeof(buffer), length);
        if (!result.complete) return result;
        // Do not join several read() snapshots: sel_read_sidtab_hash_stats recomputes on every read.
        return {0, parse_entries(buffer, length, entries)};
    }

    IoResult read_context(char *buffer, const std::size_t capacity) {
        std::size_t length = 0;
        const auto result = read_once(kCurrent, buffer, capacity, length);
        if (!result.complete) return result;
        while (length && (buffer[length - 1] == '\n' || buffer[length - 1] == '\0')) buffer[--length] = 0;
        return {0, length > 0};
    }

    IoResult check_context(const char *context, bool &canonical_match) {
        canonical_match = false;
        const int fd = open(kContext, O_RDWR | O_CLOEXEC);
        if (fd < 0) return {errno, false};
        const std::size_t length = std::strlen(context) + 1;
        // A selinuxfs transaction must be one write; do not retry or append a partial transaction.
        const ssize_t written = write(fd, context, length);
        const int error = written < 0 ? errno : 0;
        if (written != static_cast<ssize_t>(length)) {
            close(fd);
            return {error, false};
        }
        char canonical[kContextBytes]{};
        const ssize_t count = read(fd, canonical, sizeof(canonical));
        const int read_error = count < 0 ? errno : 0;
        close(fd);
        if (count <= 0 || count >= static_cast<ssize_t>(sizeof(canonical))) return {read_error, false};
        // sel_write_context returns the canonical string including its NUL terminator.
        canonical_match = count == static_cast<ssize_t>(length) && std::memcmp(canonical, context, length) == 0;
        return {0, canonical_match};
    }

    IoResult write_current(const char *context) {
        const int fd = open(kCurrent, O_WRONLY | O_CLOEXEC);
        if (fd < 0) return {errno, false};
        const std::size_t length = std::strlen(context);
        const ssize_t written = write(fd, context, length);
        const int error = written < 0 ? errno : 0;
        close(fd);
        return {error, written == static_cast<ssize_t>(length), true};
    }
} // namespace duckdetector::selinux::sidtab

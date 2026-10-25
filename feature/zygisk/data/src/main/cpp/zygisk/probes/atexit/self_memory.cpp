// SPDX-License-Identifier: Apache-2.0
#include "zygisk/probes/atexit/self_memory.h"

#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <limits>
#include <unistd.h>

namespace duckdetector::zygisk::atexit {
    SelfMemory::SelfMemory() {
        int fds[2] = {-1, -1};
#if defined(__linux__)
        if (pipe2(fds, O_CLOEXEC | O_NONBLOCK) != 0) { error_ = errno; return; }
#else
        // Host fixture adapter; Android creates both descriptors atomically with pipe2.
        if (pipe(fds) != 0) { error_ = errno; return; }
#endif
        read_fd_ = fds[0];
        write_fd_ = fds[1];
#if !defined(__linux__)
        for (int fd : fds) {
            if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0 || fcntl(fd, F_SETFL, O_NONBLOCK) < 0) { fail(errno); return; }
        }
#endif
    }

    SelfMemory::~SelfMemory() {
        if (read_fd_ >= 0) close(read_fd_);
        if (write_fd_ >= 0) close(write_fd_);
    }

    bool SelfMemory::fail(int error) {
        error_ = error;
        if (read_fd_ >= 0) close(read_fd_);
        if (write_fd_ >= 0) close(write_fd_);
        read_fd_ = write_fd_ = -1;
        return false;
    }

    bool SelfMemory::read(uintptr_t address, void *out, size_t bytes) {
        if (!available()) return false;
        if (bytes > std::numeric_limits<uintptr_t>::max() - address) return fail(EFAULT);
        size_t copied = 0;
        int interruptions = 0;
        while (copied < bytes) {
            // ACK PIPE_BUF is 4096; one outstanding chunk fits an empty pipe on 4/16 KiB systems.
            const size_t chunk = std::min<size_t>(4096, bytes - copied);
            const ssize_t sent = write(write_fd_, reinterpret_cast<const void *>(address + copied), chunk);
            if (sent < 0 && errno == EINTR && ++interruptions <= 4) continue;
            if (sent <= 0) return fail(sent == 0 ? EIO : errno);
            size_t received = 0;
            while (received < static_cast<size_t>(sent)) {
                const ssize_t got = ::read(read_fd_, static_cast<char *>(out) + copied + received, sent - received);
                if (got < 0 && errno == EINTR && ++interruptions <= 4) continue;
                if (got <= 0) return fail(got == 0 ? EIO : errno);
                received += static_cast<size_t>(got);
            }
            copied += static_cast<size_t>(sent);
        }
        return true;
    }
}

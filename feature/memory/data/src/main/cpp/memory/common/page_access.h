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

#ifndef DUCKDETECTOR_MEMORY_COMMON_PAGE_ACCESS_H
#define DUCKDETECTOR_MEMORY_COMMON_PAGE_ACCESS_H

#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace duckdetector::memory {

    class ScopedFd {
    public:
        explicit ScopedFd(const int fd = -1) : fd_(fd) {}
        ~ScopedFd() { reset(); }

        ScopedFd(const ScopedFd &) = delete;
        ScopedFd &operator=(const ScopedFd &) = delete;

        int get() const { return fd_; }
        bool valid() const { return fd_ >= 0; }

        void reset(const int new_fd = -1) {
            if (fd_ >= 0) {
                close(fd_);
            }
            fd_ = new_fd;
        }

    private:
        int fd_ = -1;
    };

    enum class PageResidency : std::uint8_t {
        kNotPresent,
        kSwapped,
        kFilePage,
        kAnonymousPage,
    };

    // Reads this process's /proc/self/pagemap. Only the flag bits are used: without CAP_SYS_ADMIN
    // the kernel zeroes the frame number but still reports present, swapped and file-page
    // (Documentation/admin-guide/mm/pagemap.rst), and pagemap_read() walks the page tables
    // without pinning any page.
    class PagemapReader {
    public:
        PagemapReader();

        bool available() const { return fd_.valid(); }

        // One entry per page of [start, start + count * page_size); false when the read fails.
        bool read(
                std::uintptr_t start,
                std::size_t count,
                std::size_t page_size,
                std::vector<PageResidency> &out
        ) const;

    private:
        ScopedFd fd_;
    };

    // Copies this process's memory through a pipe. write(2) reads the source with
    // copy_from_user, so a page unmapped meanwhile fails with EFAULT instead of SIGSEGV, and
    // nothing pins the page: process_vm_readv and /proc/self/mem go through get_user_pages, which
    // on kernels with the forced COW break makes a private copy of the very file page they read.
    class PipeMemoryReader {
    public:
        PipeMemoryReader();

        bool available() const { return read_end_.valid() && write_end_.valid(); }

        // False when any byte of [address, address + size) could not be read.
        bool read(std::uintptr_t address, std::size_t size, std::uint8_t *out);

    private:
        void drain();

        ScopedFd read_end_;
        ScopedFd write_end_;
    };

}  // namespace duckdetector::memory

#endif  // DUCKDETECTOR_MEMORY_COMMON_PAGE_ACCESS_H

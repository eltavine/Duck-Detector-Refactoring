// SPDX-License-Identifier: Apache-2.0
#include "zygisk/probes/atexit/table.h"
#include "zygisk/probes/atexit/libc_objects.h"
#include "zygisk/probes/atexit/self_memory.h"

#include <android/api-level.h>
#include <cerrno>
#include <dlfcn.h>
#include <fcntl.h>
#include <limits>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

namespace duckdetector::zygisk::atexit {
    namespace {
        constexpr size_t kMaxEntries = 65536;
        constexpr size_t kMaxImage = 32 * 1024 * 1024;

        struct File {
            int fd;
            explicit File(const char *path) : fd(open(path, O_RDONLY | O_CLOEXEC)) {}
            ~File() { if (fd >= 0) close(fd); }
            File(const File &) = delete;
            File &operator=(const File &) = delete;
        };

        bool read_at(int fd, uintptr_t address, void *out, size_t bytes) {
            if (address > uint64_t(std::numeric_limits<off64_t>::max()) ||
                bytes > uint64_t(std::numeric_limits<off64_t>::max()) - address) return false;
            size_t done = 0;
            int interruptions = 0;
            while (done < bytes) {
                const auto count = pread64(fd, static_cast<char *>(out) + done, bytes - done, address + done);
                if (count < 0 && errno == EINTR && ++interruptions <= 4) continue;
                if (count == 0) errno = EIO;
                if (count <= 0) return false;
                done += static_cast<size_t>(count);
            }
            return true;
        }

        bool covered(const std::vector<MapEntry> &maps, uintptr_t start, size_t bytes, bool writable = false) {
            if (bytes > std::numeric_limits<uintptr_t>::max() - start) return false;
            const uintptr_t end = start + bytes;
            for (const auto &map : maps) {
                if (map.end <= start) continue;
                if (map.start > start || !map.readable() || (writable && !map.writable())) return false;
                if (map.end >= end) return true;
                start = map.end;
            }
            return false;
        }

        Table failure(TableState state, const std::string &detail) {
            Table out;
            out.state = state;
            out.detail = detail;
            return out;
        }

        Table io_failure(const char *operation, int error) {
            return failure(error == EACCES || error == EPERM ? TableState::kPermissionDenied : TableState::kUnavailable,
                           std::string(operation) + " failed (errno " + std::to_string(error) + ").");
        }
    }

    Table read_table(const std::vector<MapEntry> &maps) {
        // These release tags have the reviewed AtexitArray layout; private ABI changes fail closed.
        const int api = android_get_device_api_level();
        if (api < 30 || api > 37) return failure(TableState::kUnsupported, "Exit-handler layout is reviewed for Android 11–17.");
        void *entry = dlsym(RTLD_DEFAULT, "__cxa_atexit");
        Dl_info info{};
        if (entry == nullptr || dladdr(entry, &info) == 0 || info.dli_fname == nullptr || info.dli_fbase == nullptr) {
            return failure(TableState::kUnavailable, "Cannot identify the loaded libc image.");
        }
        const std::string path(info.dli_fname);
        if (path.substr(path.find_last_of('/') + 1) != "libc.so") {
            return failure(TableState::kUnavailable, "The atexit entry point does not belong to libc.");
        }
        File image_file(path.c_str());
        if (image_file.fd < 0) return io_failure("Opening libc", errno);
        struct stat stat{};
        if (fstat(image_file.fd, &stat) != 0) return io_failure("Inspecting libc", errno);
        // A replaced file/mount can retain the same pathname but have a different private layout.
        const auto *loaded = find_map_for_address(maps, reinterpret_cast<uintptr_t>(entry));
        if (loaded == nullptr || loaded->inode == 0 || loaded->inode != stat.st_ino ||
            loaded->device_major != major(stat.st_dev) || loaded->device_minor != minor(stat.st_dev)) {
            return failure(TableState::kUnavailable, "The loaded libc mapping and symbol file have different identities.");
        }
        if (stat.st_size <= 0 || uint64_t(stat.st_size) > kMaxImage) {
            return failure(TableState::kUnsupported, "Libc image exceeds the bounded symbol-reader size.");
        }
        std::vector<uint8_t> image(static_cast<size_t>(stat.st_size));
        if (!read_at(image_file.fd, 0, image.data(), image.size())) return io_failure("Reading libc symbols", errno);
        const auto objects = locate_objects(image, reinterpret_cast<uintptr_t>(info.dli_fbase));
        if (objects.state != ObjectState::kFound) {
            return failure(objects.state == ObjectState::kMalformed ? TableState::kInvalid : TableState::kUnsupported,
                           "Libc local exit-handler array/lock symbols are missing or incompatible.");
        }
        if (objects.mutex_size != sizeof(pthread_mutex_t) || objects.mutex % alignof(pthread_mutex_t) != 0 ||
            !covered(maps, objects.mutex, sizeof(pthread_mutex_t), true)) {
            return failure(TableState::kUnsupported, "Libc exit-handler lock layout is incompatible.");
        }
        for (size_t i = 0; i < objects.fields.size(); ++i) {
            if (!covered(maps, objects.fields[i], i == 4 ? sizeof(uint64_t) : sizeof(uintptr_t))) {
                return failure(TableState::kUnavailable, "Libc exit-handler metadata is outside readable mappings.");
            }
        }
        SelfMemory memory;
        if (!memory.available()) return io_failure("Creating a private memory-copy pipe", memory.error());

        // Allocate before taking libc's lock; no allocator, loader, logging or callbacks inside it.
        std::vector<Entry> entries(kMaxEntries);
        auto *mutex = reinterpret_cast<pthread_mutex_t *>(objects.mutex);
        const int lock_error = pthread_mutex_trylock(mutex);
        if (lock_error != 0) {
            return failure(lock_error == EBUSY ? TableState::kBusy : TableState::kUnavailable,
                           "Libc exit-handler lock is unavailable (error " + std::to_string(lock_error) + ").");
        }
        std::array<uintptr_t, 4> values{};
        uint64_t appends = 0;
        bool readable = true;
        for (size_t i = 0; i < values.size(); ++i) {
            readable = readable && memory.read(objects.fields[i], &values[i], sizeof(uintptr_t));
        }
        readable = readable && memory.read(objects.fields[4], &appends, sizeof(appends));
        const uintptr_t pointer = values[0];
        const size_t size = values[1], extracted = values[2], capacity = values[3];
        const bool bounded = size <= kMaxEntries && capacity <= kMaxEntries;
        const bool valid = readable && size <= capacity && extracted <= size &&
                           appends >= size && (size == 0 || (pointer != 0 && pointer % alignof(Entry) == 0));
        bool table_read = false;
        if (valid && bounded && (size == 0 || covered(maps, pointer, size * sizeof(Entry)))) {
            table_read = memory.read(pointer, entries.data(), size * sizeof(Entry));
        }
        const int read_error = memory.error();
        const int unlock_error = pthread_mutex_unlock(mutex);
        if (unlock_error != 0) return failure(TableState::kUnavailable, "Libc exit-handler lock release failed.");
        if (!readable) return io_failure("Reading exit-handler metadata", read_error);
        if (!valid) return failure(TableState::kInvalid, "Libc exit-handler counts or layout failed validation.");
        if (!bounded) return failure(TableState::kUnsupported, "Exit-handler table exceeds the bounded reader capacity.");
        if (!table_read) return failure(TableState::kUnavailable, "Exit-handler pages changed or could not be read.");
        entries.resize(size);
        const auto nulls = std::count_if(entries.begin(), entries.end(), [](const Entry &e) { return e.empty(); });
        if (static_cast<size_t>(nulls) != extracted) {
            return failure(TableState::kInvalid, "Exit-handler null count disagrees with libc metadata.");
        }
        Table out;
        out.state = TableState::kCollected;
        out.entries = std::move(entries);
        out.detail = "Read " + std::to_string(size) + " exit handlers under libc's mutex from this process; " +
                     std::to_string(nulls) + " cleared entries. Normal finalization can also leave cleared entries.";
        return out;
    }
}  // namespace duckdetector::zygisk::atexit

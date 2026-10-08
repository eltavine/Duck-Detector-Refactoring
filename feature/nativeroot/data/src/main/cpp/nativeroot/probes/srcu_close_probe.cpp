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

#include "srcu_close_probe.h"

#include <atomic>
#include <cerrno>
#include <pthread.h>
#include <semaphore.h>
#include <sys/inotify.h>
#include <time.h>
#include <unistd.h>

namespace duckdetector::nativeroot {
namespace {
constexpr std::size_t kSampleLimit = 128;
int init_watch() { return inotify_init1(IN_CLOEXEC | IN_NONBLOCK); }
int add_watch(int fd, const char *directory) { return inotify_add_watch(fd, directory, IN_ATTRIB); }
std::int64_t monotonic_now() {
    timespec time{};
    if (clock_gettime(CLOCK_MONOTONIC, &time) != 0) return 0;
    return static_cast<std::int64_t>(time.tv_sec) * 1000000000 + time.tv_nsec;
}
void pause_sample() {
    timespec remaining{0, 1000000};
    while (nanosleep(&remaining, &remaining) != 0 && errno == EINTR) { }
}
const CloseIo kIo{init_watch, add_watch, ::close, monotonic_now, pause_sample};
struct Worker {
    const char *directory;
    const CloseIo *io;
    CloseWindow *window;
    std::atomic<bool> done{false};
    sem_t ready{}, start{};
};

CloseSample prepare(const Worker &worker, int &fd) {
    CloseSample sample;
    fd = worker.io->init();
    if (fd < 0) {
        sample.stage = CloseStage::INIT_FAILED;
        sample.error = errno;
    } else if (worker.io->watch(fd, worker.directory) < 0) {
        sample.stage = CloseStage::WATCH_FAILED;
        sample.error = errno;
        worker.io->close_fd(fd);
        fd = -1;
    }
    return sample;
}
void *sample_worker(void *arg) {
    auto &worker = *static_cast<Worker *>(arg);
    int fd = -1;
    auto sample = prepare(worker, fd);
    if (sample.stage != CloseStage::OK) worker.window->samples.push_back(sample);
    sem_post(&worker.ready);
    while (sem_wait(&worker.start) != 0 && errno == EINTR) { }
    if (sample.stage != CloseStage::OK) return nullptr;
    do {
        // ACK inotify_release -> destroy_group -> flush reaper -> synchronize_srcu.
        // Keep clock reads and the entire close in this translation unit. No JNI or logging here.
        sample.begin = worker.io->now();
        const int begin_error = sample.begin ? 0 : errno;
        const int result = worker.io->close_fd(fd);
        const int saved_error = errno;
        sample.end = worker.io->now();
        if (!sample.begin || sample.end < sample.begin) {
            sample.stage = CloseStage::CLOCK_FAILED;
            sample.error = begin_error ? begin_error : (!sample.end ? errno : 0);
        }
        else if (result != 0) { sample.stage = CloseStage::CLOSE_FAILED; sample.error = saved_error; }
        // Never retry close(EINTR): the descriptor may already have been released and reused.
        fd = -1;
        worker.window->samples.push_back(sample);
        if (sample.stage != CloseStage::OK || worker.done.load(std::memory_order_acquire)) break;
        if (worker.window->samples.size() == kSampleLimit) {
            worker.window->saturated = true;
            break;
        }
        worker.io->pause();
        if (worker.done.load(std::memory_order_acquire)) break;
        sample = prepare(worker, fd);
        if (sample.stage != CloseStage::OK) { worker.window->samples.push_back(sample); break; }
    } while (true);
    return nullptr;
}
}  // namespace

CloseWindow measure_close_window(const char *directory, const std::function<void()> &trigger,
                                 const CloseIo *injected) {
    CloseWindow window;
    window.samples.reserve(kSampleLimit);
    Worker worker{directory, injected ? injected : &kIo, &window};
    if (sem_init(&worker.ready, 0, 0) != 0) {
        window.samples.push_back({0, 0, CloseStage::THREAD_FAILED, errno});
        return window;
    }
    if (sem_init(&worker.start, 0, 0) != 0) {
        window.samples.push_back({0, 0, CloseStage::THREAD_FAILED, errno});
        sem_destroy(&worker.ready);
        return window;
    }
    pthread_t thread;
    const int error = pthread_create(&thread, nullptr, sample_worker, &worker);
    if (error) window.samples.push_back({0, 0, CloseStage::THREAD_FAILED, error});
    else {
        while (sem_wait(&worker.ready) != 0 && errno == EINTR) { }
        // A preparation failure must not mutate PackageManager state.
        if (window.samples.empty()) {
            window.begin = worker.io->now();
            sem_post(&worker.start);
            if (window.begin) trigger();
            window.end = worker.io->now();
        } else sem_post(&worker.start);
        worker.done.store(true, std::memory_order_release);
        // This can wait in the kernel: the feature's private process watchdog bounds host waiting.
        pthread_join(thread, nullptr);
    }
    sem_destroy(&worker.start);
    sem_destroy(&worker.ready);
    return window;
}
}  // namespace duckdetector::nativeroot

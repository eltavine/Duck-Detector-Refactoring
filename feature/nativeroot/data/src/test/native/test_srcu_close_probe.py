#!/usr/bin/env python3
"""Compile the production sampler and test injected failures on a POSIX build host."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
PROBE = ROOT.parents[1] / "main/cpp/nativeroot/probes"
# Hosts need no inotify support: the test supplies all I/O functions. macOS has no unnamed
# POSIX semaphores, so use a condition-variable semaphore with the same handshake here.
SEMAPHORE = r"""
#pragma once
#include <pthread.h>
struct TestSemaphore { pthread_mutex_t lock; pthread_cond_t condition; unsigned count; };
#define sem_t TestSemaphore
inline int sem_init(TestSemaphore *s, int, unsigned value) {
    pthread_mutex_init(&s->lock, nullptr); pthread_cond_init(&s->condition, nullptr);
    s->count = value; return 0;
}
inline int sem_wait(TestSemaphore *s) {
    pthread_mutex_lock(&s->lock);
    while (!s->count) pthread_cond_wait(&s->condition, &s->lock);
    --s->count; pthread_mutex_unlock(&s->lock); return 0;
}
inline int sem_post(TestSemaphore *s) {
    pthread_mutex_lock(&s->lock); ++s->count; pthread_cond_signal(&s->condition);
    pthread_mutex_unlock(&s->lock); return 0;
}
inline int sem_destroy(TestSemaphore *s) {
    pthread_cond_destroy(&s->condition); pthread_mutex_destroy(&s->lock); return 0;
}
"""
INOTIFY = r"""
#pragma once
#include <cerrno>
#define IN_CLOEXEC 1
#define IN_NONBLOCK 2
#define IN_ATTRIB 4
inline int inotify_init1(int) { errno = ENOSYS; return -1; }
inline int inotify_add_watch(int, const char *, unsigned) { errno = ENOSYS; return -1; }
"""
with tempfile.TemporaryDirectory(prefix="srcu-close-test-") as directory:
    host = Path(directory)
    (host / "sys").mkdir()
    (host / "sys/inotify.h").write_text(INOTIFY)
    if sys.platform == "darwin":
        (host / "semaphore.h").write_text(SEMAPHORE)
    compiler = shutil.which("c++")
    if not compiler:
        raise RuntimeError("A host C++ compiler is required")
    executable = host / "sampler-test"
    subprocess.run([compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-pthread",
                    "-I", str(host), "-I", str(PROBE), str(PROBE / "srcu_close_probe.cpp"),
                    str(ROOT / "srcu_close_probe_test.cpp"), "-o", str(executable)], check=True)
    subprocess.run([str(executable)], check=True, timeout=10)
print("SRCU sampler ordering, FD cleanup, quota and injected error tests passed")

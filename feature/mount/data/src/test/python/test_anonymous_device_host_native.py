#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the production anonymous-device probe with controlled filesystem observations."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from test_mount_evidence_host_native import INTERNAL, ROOT, STATX


class AnonymousDeviceNativeTest(unittest.TestCase):
    def test_anonymous_device_observations(self):
        compiler = os.environ.get("CXX") or shutil.which("clang++") or shutil.which("g++")
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory(prefix="anonymous-device-test-") as directory:
            temporary = Path(directory)
            headers = {
                "mount/detector_internal.h": INTERNAL + '''
#include <sys/stat.h>
namespace duckdetector::mount::detail {
int syscall_stat_path(const char *, struct stat *);
bool starts_with(const std::string &, const std::string &);
}
''',
                "linux/stat.h": STATX,
                "sys/statfs.h": "#pragma once\nstruct statfs { long f_type; };\nint statfs(const char *, struct statfs *);\n",
                "sys/sysmacros.h": '''#pragma once
#include <cstdint>
#define major(dev) (static_cast<uint32_t>(dev) >> 24)
#define minor(dev) (static_cast<uint32_t>(dev) & 0xffffffU)
#define makedev(maj, min) ((static_cast<uint32_t>(maj) << 24) | (min))
''',
            }
            # glibc imports linux/stat.h itself; use its real definition there.
            import sys
            if sys.platform == "linux":
                del headers["linux/stat.h"]
            for name, content in headers.items():
                path = temporary / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            binary = temporary / "anonymous-device-test"
            subprocess.run([
                compiler, "-std=c++20", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
                "-I", str(temporary), "-I", str(ROOT / "feature/mount/data/src/main/cpp"),
                str(ROOT / "feature/mount/data/src/test/native/anonymous_device_probe_test.cpp"),
                "-o", str(binary),
            ], check=True)
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()

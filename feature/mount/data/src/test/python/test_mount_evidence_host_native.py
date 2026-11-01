#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute mount-table and collection code on the host with injected platform I/O."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[6]
INTERNAL = r'''
#pragma once
#include "mount/detector_core.h"
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>
#include <linux/stat.h>
#undef __NR_openat
#define __NR_openat 1001
#undef __NR_read
#define __NR_read 1002
#undef __NR_close
#define __NR_close 1003
#undef __NR_newfstatat
#define __NR_newfstatat 1004
#undef __NR_fstatat64
#define __NR_fstatat64 1005
#undef __NR_readlinkat
#define __NR_readlinkat 1006
#undef __NR_statx
#define __NR_statx 1007
#ifndef AT_NO_AUTOMOUNT
#define AT_NO_AUTOMOUNT 0x800
#endif
namespace duckdetector::mount::detail {
struct MountEntry { std::string source, target, fsType, options; };
struct MountInfoEntry {
    int id = 0, parentId = 0;
    unsigned int major = 0, minor = 0;
    std::string root, target, options;
    std::vector<std::string> optionalFields;
    std::string fsType, source, superOptions;
};
enum class AccessResult { Exists, NotExists, PermissionDenied };
constexpr unsigned int kStatxMountIdMask = 0x1000, kStatxMountRootMask = 0x2000;
inline bool is_statx_supported() { return true; }
int syscall_open_readonly(const char *, int = O_RDONLY | O_CLOEXEC);
std::string lowercase_copy(std::string);
std::string read_file_direct(const char *, size_t, bool * = nullptr);
std::vector<MountInfoEntry> parse_mount_info(const std::string &, bool * = nullptr);
}
'''
STATX = r'''
#pragma once
#include <cstdint>
#define STATX_BASIC_STATS 0x7ff
struct statx {
    unsigned int stx_mask = 0;
    uint64_t stx_mnt_id = 0, stx_attributes = 0, stx_attributes_mask = 0;
};
'''


class MountEvidenceNativeTest(unittest.TestCase):
    def test_platform_counterexamples(self):
        compiler = os.environ.get("CXX") or shutil.which("clang++") or shutil.which("g++")
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory(prefix="mount-evidence-test-") as directory:
            temporary = Path(directory)
            headers = {
                "mount/detector_internal.h": INTERNAL,
                "linux/magic.h": "#pragma once\n#define OVERLAYFS_SUPER_MAGIC 0x794c7630\n#define TMPFS_MAGIC 0x01021994\n",
                "sys/statfs.h": "#pragma once\nextern long testFsType;\nstruct statfs { long f_type; };\ninline int statfs(const char *, struct statfs *value) { value->f_type = testFsType; return 0; }\n",
                "android/log.h": "#pragma once\n",
            }
            # glibc also imports linux/stat.h; preserve its native statx definition.
            if sys.platform != "linux":
                headers["linux/stat.h"] = STATX
            for name, content in headers.items():
                path = temporary / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            binary = temporary / "mount-evidence-test"
            subprocess.run([
                compiler, "-std=c++20", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
                "-I", str(temporary), "-I", str(ROOT / "feature/mount/data/src/main/cpp"),
                "-I", str(ROOT / "core/native/src/main/cpp"),
                "-I", str(ROOT / "capability/earlypreload/data/src/main/cpp"),
                str(ROOT / "feature/mount/data/src/test/native/mount_evidence_test.cpp"),
                "-o", str(binary),
            ], check=True)
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()

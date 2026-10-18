# Copyright 2026 Duck Apps Contributor
# If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Compile the production seccomp probe and run disposable-filter cases on Android."""
import argparse
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ndk', type=Path, required=True)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--adb', default='adb')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[6]
    prebuilt = args.ndk / 'toolchains/llvm/prebuilt'
    compilers = list(prebuilt.glob('*/bin/aarch64-linux-android29-clang++'))
    if len(compilers) != 1:
        parser.error('Expected one host NDK compiler for arm64 API 29')
    feature = root / 'feature/dangerousapps/data/src'
    common = root / 'core/native/src/main/cpp'
    native = feature / 'main/cpp/dangerousapps'
    with tempfile.TemporaryDirectory(prefix='duck-seccomp-test-') as folder:
        binary = Path(folder) / 'seccomp_uid_test'
        command = [str(compilers[0]), '-std=c++23', '-static-libstdc++', '-pthread',
                   '-I' + str(native), '-I' + str(common),
                   str(feature / 'test/cpp/seccomp_uid_probe_test.cpp'),
                   str(native / 'seccomp_uid_bridge.cpp'), str(native / 'seccomp_uid_query.cpp'),
                   str(common / 'common/disposable_child.cpp'), '-ldl', '-o', str(binary)]
        subprocess.run(command, check=True)
        adb = [args.adb, '-s', args.serial]
        target = '/data/local/tmp/' + Path(folder).name
        try:
            subprocess.run(adb + ['push', str(binary), target], check=True)
            subprocess.run(adb + ['shell', 'chmod', '700', target], check=True)
            subprocess.run(adb + ['shell', target], check=True, timeout=30)
        finally:
            subprocess.run(adb + ['shell', 'rm', '-f', target], check=False)


if __name__ == '__main__':
    main()

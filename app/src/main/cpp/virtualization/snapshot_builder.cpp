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

#include "virtualization/snapshot_builder.h"
#include "virtualization/egl_probe.h"

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace duckdetector::virtualization {

    namespace {

        std::string read_property(const char *name) {
            char value[PROP_VALUE_MAX] = {0};
            if (__system_property_get(name, value) > 0) {
                return std::string(value);
            }
            return "";
        }

        bool file_exists(const char *path) {
            struct stat st{};
            return stat(path, &st) == 0;
        }

        std::string read_cmdline() {
            std::ifstream input("/proc/self/cmdline", std::ios::binary);
            if (!input.is_open()) {
                return "";
            }
            std::string data(
                    (std::istreambuf_iterator<char>(input)),
                    std::istreambuf_iterator<char>()
            );
            std::replace(data.begin(), data.end(), '\0', ' ');
            return data;
        }

        std::string encode_value(const std::string &value) {
            std::string encoded = value;
            std::size_t pos = 0;
            while ((pos = encoded.find('\n', pos)) != std::string::npos) {
                encoded.replace(pos, 1, "\\n");
                pos += 2;
            }
            pos = 0;
            while ((pos = encoded.find('\r', pos)) != std::string::npos) {
                encoded.replace(pos, 1, "\\r");
                pos += 2;
            }
            return encoded;
        }

        bool contains_token(const std::string &text, const std::vector<std::string> &tokens) {
            for (const auto &token: tokens) {
                if (text.find(token) != std::string::npos) {
                    return true;
                }
            }
            return false;
        }

        std::string lowercase_copy(std::string value) {
            std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
                return static_cast<char>(::tolower(ch));
            });
            return value;
        }

        std::string read_link_target(const char *path) {
            char buffer[PATH_MAX] = {0};
            const ssize_t read = readlink(path, buffer, sizeof(buffer) - 1);
            if (read <= 0) {
                return "";
            }
            return std::string(buffer, static_cast<std::size_t>(read));
        }

        std::string mount_anchor_key(
                const std::string &mount_id,
                const std::string &major_minor,
                const std::string &root,
                const std::string &mount_point,
                const std::string &fs_type,
                const std::string &source
        ) {
            return mount_id + "|" + major_minor + "|" + root + "|" + mount_point + "|" +
                   fs_type + "|" + source;
        }

        void add_finding(
                Snapshot &snapshot,
                std::set<std::string> &dedupe,
                const std::string &group,
                const std::string &severity,
                const std::string &label,
                const std::string &value,
                const std::string &detail
        ) {
            const std::string key =
                    group + "|" + severity + "|" + label + "|" + value + "|" + detail;
            if (!dedupe.insert(key).second) {
                return;
            }
            snapshot.findings.push_back(SnapshotFinding{
                    group,
                    severity,
                    label,
                    value,
                    detail,
            });
            if (severity == "WARNING" || severity == "DANGER") {
                if (group == "ENVIRONMENT") {
                    snapshot.environmentHitCount += 1;
                } else if (group == "TRANSLATION") {
                    snapshot.translationHitCount += 1;
                } else if (group == "RUNTIME") {
                    snapshot.runtimeArtifactHitCount += 1;
                }
            }
        }

        void scan_properties(Snapshot &snapshot, std::set<std::string> &dedupe) {
            const std::string roKernelQemu = read_property("ro.kernel.qemu");
            if (roKernelQemu == "1") {
                add_finding(
                        snapshot,
                        dedupe,
                        "ENVIRONMENT",
                        "DANGER",
                        "ro.kernel.qemu",
                        "Guest",
                        "ro.kernel.qemu=1 is a direct emulator guest property."
                );
            }

            const std::string roBootQemu = read_property("ro.boot.qemu");
            const std::string avdName = read_property("ro.boot.qemu.avd_name");
            const std::string qemuLcd = read_property("qemu.sf.lcd_density");
            if ((!roBootQemu.empty() && roBootQemu != "0") || !avdName.empty() ||
                !qemuLcd.empty()) {
                std::ostringstream detail;
                if (!roBootQemu.empty()) {
                    detail << "ro.boot.qemu=" << roBootQemu << "\n";
                }
                if (!avdName.empty()) {
                    detail << "ro.boot.qemu.avd_name=" << avdName << "\n";
                }
                if (!qemuLcd.empty()) {
                    detail << "qemu.sf.lcd_density=" << qemuLcd;
                }
                add_finding(
                        snapshot,
                        dedupe,
                        "ENVIRONMENT",
                        "DANGER",
                        "QEMU guest properties",
                        "Present",
                        detail.str()
                );
            }

            const std::vector<std::pair<std::string, std::string>> hardware_props = {
                    {"ro.hardware",       read_property("ro.hardware")},
                    {"ro.boot.hardware",  read_property("ro.boot.hardware")},
                    {"ro.product.board",  read_property("ro.product.board")},
                    {"ro.board.platform", read_property("ro.board.platform")},
            };
            std::ostringstream hardware_detail;
            bool has_hardware_cluster = false;
            for (const auto &entry: hardware_props) {
                if (entry.second.find("goldfish") != std::string::npos ||
                    entry.second.find("ranchu") != std::string::npos) {
                    has_hardware_cluster = true;
                    hardware_detail << entry.first << "=" << entry.second << "\n";
                }
            }
            if (has_hardware_cluster) {
                add_finding(
                        snapshot,
                        dedupe,
                        "ENVIRONMENT",
                        "DANGER",
                        "Emulator hardware props",
                        "goldfish/ranchu",
                        hardware_detail.str()
                );
            }

            const std::string nativeBridge = read_property("ro.dalvik.vm.native.bridge");
            if (!nativeBridge.empty() && nativeBridge != "0") {
                add_finding(
                        snapshot,
                        dedupe,
                        "TRANSLATION",
                        "WARNING",
                        "ro.dalvik.vm.native.bridge",
                        nativeBridge,
                        "ART native bridge is configured for translated execution."
                );
            }

            const std::string hypervisorSupported = read_property(
                    "ro.boot.hypervisor.vm.supported");
            if (!hypervisorSupported.empty() && hypervisorSupported != "0") {
                add_finding(
                        snapshot,
                        dedupe,
                        "ENVIRONMENT",
                        "INFO",
                        "Hypervisor capability",
                        hypervisorSupported,
                        "Capability-only signal. It does not imply the current process is inside a guest."
                );
            }
        }

        void scan_device_nodes(Snapshot &snapshot, std::set<std::string> &dedupe) {
            const std::vector<const char *> nodes = {
                    "/dev/qemu_pipe",
                    "/dev/qemu_trace",
                    "/dev/goldfish_pipe",
                    "/dev/socket/qemud",
            };
            for (const auto *node: nodes) {
                if (file_exists(node)) {
                    add_finding(
                            snapshot,
                            dedupe,
                            "RUNTIME",
                            "DANGER",
                            "Emulator device node",
                            node,
                            std::string("Current app context can see emulator device node: ") + node
                    );
                }
            }
        }

        void scan_maps(Snapshot &snapshot, std::set<std::string> &dedupe) {
            std::ifstream input("/proc/self/maps");
            if (!input.is_open()) {
                return;
            }

            const std::vector<std::string> translation_tokens = {
                    "libhoudini.so",
                    "libnb.so",
                    "libndk_translation.so",
            };
            std::set<std::string> avf_tokens;
            std::string line;
            while (std::getline(input, line)) {
                snapshot.mapLineCount += 1;

                for (const auto &token: translation_tokens) {
                    if (line.find(token) != std::string::npos) {
                        add_finding(
                                snapshot,
                                dedupe,
                                "TRANSLATION",
                                "WARNING",
                                "Mapped translation library",
                                token,
                                line
                        );
                    }
                }

                if (line.find("goldfish") != std::string::npos ||
                    line.find("ranchu") != std::string::npos ||
                    line.find("qemu") != std::string::npos) {
                    add_finding(
                            snapshot,
                            dedupe,
                            "RUNTIME",
                            "DANGER",
                            "Mapped emulator library",
                            "Present",
                            line
                    );
                }

                if (line.find("authfs") != std::string::npos) avf_tokens.insert("authfs");
                if (line.find("virtiofs") != std::string::npos) avf_tokens.insert("virtiofs");
                if (line.find("crosvm") != std::string::npos) avf_tokens.insert("crosvm");
                if (line.find("microdroid") != std::string::npos) avf_tokens.insert("microdroid");
            }

            if (avf_tokens.size() >= 2) {
                std::ostringstream joined;
                bool first = true;
                for (const auto &token: avf_tokens) {
                    if (!first) joined << ", ";
                    joined << token;
                    first = false;
                }
                add_finding(
                        snapshot,
                        dedupe,
                        "RUNTIME",
                        "DANGER",
                        "AVF runtime",
                        joined.str(),
                        "Multiple AVF or Microdroid runtime tokens were visible from /proc/self/maps."
                );
            }
        }

        void scan_mountinfo(Snapshot &snapshot, std::set<std::string> &dedupe) {
            std::ifstream input("/proc/self/mountinfo");
            if (!input.is_open()) {
                return;
            }

            bool authfs_seen = false;
            bool avf_other_seen = false;
            std::string line;
            while (std::getline(input, line)) {
                snapshot.mountInfoCount += 1;
                if (line.find("authfs") != std::string::npos) {
                    authfs_seen = true;
                }
                if (line.find("virtiofs") != std::string::npos ||
                    line.find("microdroid") != std::string::npos ||
                    line.find("crosvm") != std::string::npos) {
                    avf_other_seen = true;
                }

                const auto separator = line.find(" - ");
                if (separator == std::string::npos) {
                    continue;
                }
                std::istringstream left(line.substr(0, separator));
                std::istringstream right(line.substr(separator + 3));
                std::string mount_id;
                std::string parent_id;
                std::string major_minor;
                std::string root;
                std::string mount_point;
                if (!(left >> mount_id >> parent_id >> major_minor >> root >> mount_point)) {
                    continue;
                }

                std::string fs_type;
                std::string source;
                if (!(right >> fs_type >> source)) {
                    continue;
                }

                const std::string anchor_key = mount_anchor_key(
                        mount_id,
                        major_minor,
                        root,
                        mount_point,
                        fs_type,
                        source
                );
                if (mount_point == "/apex") snapshot.apexMountKey = anchor_key;
                if (mount_point == "/system") snapshot.systemMountKey = anchor_key;
                if (mount_point == "/vendor") snapshot.vendorMountKey = anchor_key;

                if ((mount_point == "/apex" || mount_point == "/system" ||
                     mount_point == "/vendor") &&
                    contains_token(fs_type + " " + source,
                                   {"authfs", "virtiofs", "microdroid", "crosvm"})) {
                    add_finding(
                            snapshot,
                            dedupe,
                            "RUNTIME",
                            "DANGER",
                            "Mount anchor artifact",
                            mount_point,
                            anchor_key
                    );
                }
            }

            if (authfs_seen) {
                add_finding(
                        snapshot,
                        dedupe,
                        "RUNTIME",
                        "DANGER",
                        "authfs runtime",
                        "Present",
                        "authfs mount was visible from /proc/self/mountinfo."
                );
            }
            if (authfs_seen && avf_other_seen) {
                add_finding(
                        snapshot,
                        dedupe,
                        "RUNTIME",
                        "DANGER",
                        "AVF runtime",
                        "Present",
                        "Mount table contains authfs together with additional AVF or Microdroid tokens."
                );
            }
        }

        void scan_mount_namespace(Snapshot &snapshot) {
            snapshot.mountNamespaceInode = read_link_target("/proc/self/ns/mnt");
        }

        void scan_fd_targets(Snapshot &snapshot, std::set<std::string> &dedupe) {
            DIR *dir = opendir("/proc/self/fd");
            if (dir == nullptr) {
                return;
            }

            std::vector<std::string> translation_tokens = {
                    "libhoudini.so",
                    "libnb.so",
                    "libndk_translation.so",
            };

            struct dirent *entry = nullptr;
            while ((entry = readdir(dir)) != nullptr) {
                if (entry->d_name[0] == '.') {
                    continue;
                }
                snapshot.fdCount += 1;
                const std::string path = std::string("/proc/self/fd/") + entry->d_name;
                char buffer[PATH_MAX] = {0};
                const ssize_t read = readlink(path.c_str(), buffer, sizeof(buffer) - 1);
                if (read <= 0) {
                    continue;
                }
                std::string target(buffer, static_cast<std::size_t>(read));

                for (const auto &token: translation_tokens) {
                    if (target.find(token) != std::string::npos) {
                        add_finding(
                                snapshot,
                                dedupe,
                                "TRANSLATION",
                                "WARNING",
                                "FD target translation residue",
                                token,
                                target
                        );
                    }
                }

                if (contains_token(target, {"qemu", "goldfish", "ranchu", "authfs", "crosvm",
                                            "microdroid"})) {
                    add_finding(
                            snapshot,
                            dedupe,
                            "RUNTIME",
                            "DANGER",
                            "FD target runtime artifact",
                            "Present",
                            target
                    );
                }
            }
            closedir(dir);
        }

        void scan_cmdline(Snapshot &snapshot, std::set<std::string> &dedupe) {
            const std::string cmdline = read_cmdline();
            if (cmdline.find("-Xnative-bridge") != std::string::npos) {
                add_finding(
                        snapshot,
                        dedupe,
                        "TRANSLATION",
                        "WARNING",
                        "Cmdline native bridge",
                        "Present",
                        cmdline
                );
            }
        }

        void scan_renderer(Snapshot &snapshot, std::set<std::string> &dedupe) {
            const auto renderer = collect_renderer_snapshot();
            snapshot.eglAvailable = renderer.available;
            snapshot.eglVendor = renderer.vendor;
            snapshot.eglRenderer = renderer.renderer;
            snapshot.eglVersion = renderer.version;
            if (!renderer.available) {
                return;
            }
            const std::string lowered = lowercase_copy(
                    renderer.renderer + " " + renderer.vendor + " " + renderer.version
            );
            if (contains_token(lowered,
                               {"android emulator opengl es translator", "gfxstream", "virgl",
                                "virtio_gpu", "crosvm"})) {
                add_finding(
                        snapshot,
                        dedupe,
                        "RUNTIME",
                        "WARNING",
                        "Graphics renderer",
                        renderer.renderer.empty() ? "Detected" : renderer.renderer,
                        renderer.vendor + "\n" + renderer.renderer + "\n" + renderer.version
                );
            } else if (contains_token(lowered, {"swiftshader"})) {
                add_finding(
                        snapshot,
                        dedupe,
                        "RUNTIME",
                        "INFO",
                        "Graphics renderer",
                        renderer.renderer.empty() ? "SwiftShader" : renderer.renderer,
                        renderer.vendor + "\n" + renderer.renderer + "\n" + renderer.version
                );
            }
        }

    }  // namespace

    Snapshot collect_snapshot() {
        Snapshot snapshot;
        snapshot.available = true;
        std::set<std::string> dedupe;

        scan_mount_namespace(snapshot);
        scan_properties(snapshot, dedupe);
        scan_device_nodes(snapshot, dedupe);
        scan_maps(snapshot, dedupe);
        scan_mountinfo(snapshot, dedupe);
        scan_fd_targets(snapshot, dedupe);
        scan_cmdline(snapshot, dedupe);
        scan_renderer(snapshot, dedupe);

        return snapshot;
    }

    std::string encode_snapshot(const Snapshot &snapshot) {
        std::ostringstream output;
        output << "AVAILABLE=" << (snapshot.available ? 1 : 0) << '\n';
        output << "EGL_AVAILABLE=" << (snapshot.eglAvailable ? 1 : 0) << '\n';
        output << "EGL_VENDOR=" << encode_value(snapshot.eglVendor) << '\n';
        output << "EGL_RENDERER=" << encode_value(snapshot.eglRenderer) << '\n';
        output << "EGL_VERSION=" << encode_value(snapshot.eglVersion) << '\n';
        output << "MOUNT_NAMESPACE_INODE=" << encode_value(snapshot.mountNamespaceInode) << '\n';
        output << "APEX_MOUNT_KEY=" << encode_value(snapshot.apexMountKey) << '\n';
        output << "SYSTEM_MOUNT_KEY=" << encode_value(snapshot.systemMountKey) << '\n';
        output << "VENDOR_MOUNT_KEY=" << encode_value(snapshot.vendorMountKey) << '\n';
        output << "MAP_LINE_COUNT=" << snapshot.mapLineCount << '\n';
        output << "FD_COUNT=" << snapshot.fdCount << '\n';
        output << "MOUNTINFO_LINE_COUNT=" << snapshot.mountInfoCount << '\n';
        output << "ENVIRONMENT_HITS=" << snapshot.environmentHitCount << '\n';
        output << "TRANSLATION_HITS=" << snapshot.translationHitCount << '\n';
        output << "RUNTIME_HITS=" << snapshot.runtimeArtifactHitCount << '\n';
        for (const auto &finding: snapshot.findings) {
            output << "FINDING="
                   << finding.group << '\t'
                   << finding.severity << '\t'
                   << finding.label << '\t'
                   << finding.value << '\t'
                   << encode_value(finding.detail) << '\n';
        }
        return output.str();
    }

}  // namespace duckdetector::virtualization

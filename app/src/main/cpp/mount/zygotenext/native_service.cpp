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

#include <ctype.h>
#include <cerrno>
#include <android/binder_ibinder.h>
#include <android/binder_parcel.h>
#include <android/native_service.h>
#include <dlfcn.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#include <fstream>
#include <cstring>
#include <cstdlib>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr int32_t kStatusOk = 0;
constexpr int32_t kStatusUnknownTransaction = -2;
constexpr uint32_t kCollectTransaction = 1;
constexpr const char *kDescriptor =
        "com.eltavine.duckdetector.features.mount.zygotenext";

using BinderClassDefine = decltype(&AIBinder_Class_define);
using BinderNew = decltype(&AIBinder_new);
using ParcelWriteInt32 = decltype(&AParcel_writeInt32);
using ParcelWriteString = decltype(&AParcel_writeString);

BinderClassDefine g_class_define = nullptr;
BinderNew g_binder_new = nullptr;
ParcelWriteInt32 g_write_int32 = nullptr;
ParcelWriteString g_write_string = nullptr;
const AIBinder_Class *g_probe_class = nullptr;
std::string g_payload;

struct MountRecord {
    uint64_t mount_id = 0;
    std::string root;
    std::string point;
    std::string file_system_type;
    std::string source;
    std::vector<std::string> optional_fields;
};

struct MarkerRecord {
    std::vector<std::string> labels;
    MountRecord mount;
    std::string raw_line;
};

std::string escape_field(const std::string &value) {
    std::string escaped;
    escaped.reserve(value.size());
    for (const char ch: value) {
        switch (ch) {
            case '\\':
                escaped += "\\\\";
                break;
            case '\n':
                escaped += "\\n";
                break;
            case '\r':
                escaped += "\\r";
                break;
            case '\t':
                escaped += "\\t";
                break;
            default:
                escaped += ch;
                break;
        }
    }
    return escaped;
}

std::vector<std::string> split_spaces(const std::string &value) {
    std::vector<std::string> fields;
    std::istringstream input(value);
    std::string field;
    while (input >> field) fields.push_back(field);
    return fields;
}

bool parse_mount_record(const std::string &line, MountRecord *record) {
    const size_t separator = line.find(" - ");
    if (separator == std::string::npos) return false;
    const auto before = split_spaces(line.substr(0, separator));
    const auto after = split_spaces(line.substr(separator + 3));
    if (before.size() < 6 || after.size() < 2) return false;
    if (before[0].empty() || before[0].find_first_not_of("0123456789") != std::string::npos) {
        return false;
    }
    errno = 0;
    char *mount_id_end = nullptr;
    const uint64_t mount_id = strtoull(before[0].c_str(), &mount_id_end, 10);
    if (errno == ERANGE || mount_id_end == before[0].c_str() || *mount_id_end != '\0' ||
        mount_id == 0) {
        return false;
    }
    record->mount_id = mount_id;
    record->root = before[3];
    record->point = before[4];
    record->optional_fields.assign(before.begin() + 6, before.end());
    record->file_system_type = after[0];
    record->source = after[1];
    return true;
}

std::string lowercase(const std::string &value) {
    std::string normalized = value;
    for (char &ch: normalized) {
        ch = static_cast<char>(tolower(static_cast<unsigned char>(ch)));
    }
    return normalized;
}

bool contains_named_marker(const std::string &text, const std::string &marker,
                           const bool require_end = true) {
    size_t start = text.find(marker);
    while (start != std::string::npos) {
        const size_t end = start + marker.size();
        const bool start_boundary = start == 0 ||
                                    !isalnum(static_cast<unsigned char>(text[start - 1]));
        const bool end_boundary = !require_end || end == text.size() ||
                                  !isalnum(static_cast<unsigned char>(text[end]));
        if (start_boundary && end_boundary) return true;
        start = text.find(marker, start + 1);
    }
    return false;
}

bool contains_path_prefix(const std::string &text, const std::string &path) {
    size_t start = text.find(path);
    while (start != std::string::npos) {
        const size_t end = start + path.size();
        const bool end_boundary = end == text.size() || text[end] == '/' ||
                                  isspace(static_cast<unsigned char>(text[end])) ||
                                  text[end] == ',' || text[end] == ':';
        if (end_boundary) return true;
        start = text.find(path, start + 1);
    }
    return false;
}

std::vector<std::string> marker_labels(const std::string &line) {
    const std::string normalized = lowercase(line);
    std::vector<std::string> labels;
    if (normalized.find("magisk") != std::string::npos) labels.emplace_back("Magisk");
    if (normalized.find("kernelsu") != std::string::npos ||
        contains_named_marker(normalized, "ksu")) {
        labels.emplace_back("KernelSU");
    }
    if (normalized.find("zygisk") != std::string::npos) labels.emplace_back("Zygisk");
    if (contains_named_marker(normalized, "zn")) labels.emplace_back("ZN");
    if (contains_named_marker(normalized, "sui")) labels.emplace_back("Sui");
    if (contains_named_marker(normalized, "lsp", false)) labels.emplace_back("LSP");
    if (contains_path_prefix(normalized, "/data/adb")) {
        labels.emplace_back("data/adb");
    } else if (contains_path_prefix(normalized, "/adb/modules")) {
        // Magisk's mountinfo parser identifies module mounts by roots such as /adb/modules.
        labels.emplace_back("ADB modules");
    }
    if (normalized.find("/debug_ramdisk") != std::string::npos) {
        labels.emplace_back("debug_ramdisk");
    }
    return labels;
}

uint64_t read_namespace_inode() {
    char target[128];
    const ssize_t length = readlink("/proc/self/ns/mnt", target, sizeof(target) - 1);
    if (length <= 0) return 0;
    target[length] = '\0';
    const char *opening = strrchr(target, '[');
    if (opening == nullptr) return 0;
    return strtoull(opening + 1, nullptr, 10);
}

std::string join(const std::vector<std::string> &values, const char separator) {
    std::ostringstream output;
    for (size_t index = 0; index < values.size(); ++index) {
        if (index != 0) output << separator;
        output << values[index];
    }
    return output.str();
}

std::string collect_payload() {
    std::ifstream mountinfo("/proc/self/mountinfo");
    std::vector<MarkerRecord> markers;
    std::string root_propagation;
    std::string error;
    uint64_t root_mount_id = 0;
    uint64_t minimum_mount_id = 0;
    uint64_t maximum_mount_id = 0;
    int mount_count = 0;
    bool readable = mountinfo.good();
    if (readable) {
        std::string line;
        while (std::getline(mountinfo, line)) {
            MountRecord record;
            if (!parse_mount_record(line, &record)) continue;
            ++mount_count;
            if (minimum_mount_id == 0 || record.mount_id < minimum_mount_id) {
                minimum_mount_id = record.mount_id;
            }
            if (record.mount_id > maximum_mount_id) maximum_mount_id = record.mount_id;
            if (record.point == "/") {
                root_mount_id = record.mount_id;
                std::vector<std::string> propagation;
                for (const auto &field: record.optional_fields) {
                    if (field.rfind("shared:", 0) == 0 || field.rfind("master:", 0) == 0) {
                        propagation.push_back(field);
                    }
                }
                root_propagation = join(propagation, ' ');
            }
            auto labels = marker_labels(line);
            if (!labels.empty()) {
                markers.push_back({std::move(labels), std::move(record), line});
            }
        }
        if (mountinfo.bad()) {
            readable = false;
            error = "Reading /proc/self/mountinfo failed before EOF.";
        }
    } else {
        error = "Opening /proc/self/mountinfo failed.";
    }

    std::ostringstream payload;
    payload << "VERSION=2\n";
    payload << "AVAILABLE=" << (readable ? '1' : '0') << '\n';
    payload << "PID=" << getpid() << '\n';
    payload << "PPID=" << getppid() << '\n';
    payload << "UID=" << getuid() << '\n';
    payload << "MOUNT_NAMESPACE=" << read_namespace_inode() << '\n';
    payload << "ROOT_PROPAGATION=" << escape_field(root_propagation) << '\n';
    payload << "ROOT_MOUNT_ID=" << root_mount_id << '\n';
    payload << "MIN_MOUNT_ID=" << minimum_mount_id << '\n';
    payload << "MAX_MOUNT_ID=" << maximum_mount_id << '\n';
    payload << "MOUNTINFO_READABLE=" << (readable ? '1' : '0') << '\n';
    payload << "MOUNT_COUNT=" << mount_count << '\n';
    payload << "ERROR=" << escape_field(error) << '\n';
    for (const auto &marker: markers) {
        payload << "MARKER="
                << escape_field(join(marker.labels, ',')) << '\t'
                << escape_field(marker.mount.point) << '\t'
                << escape_field(marker.mount.root) << '\t'
                << escape_field(marker.mount.file_system_type) << '\t'
                << escape_field(marker.mount.source) << '\t'
                << escape_field(marker.raw_line) << '\n';
    }
    return payload.str();
}

void *binder_on_create(void *args) {
    return args;
}

void binder_on_destroy(void *) {}

int32_t binder_on_transact(AIBinder *, const uint32_t code, const AParcel *, AParcel *output) {
    if (code != kCollectTransaction || g_write_int32 == nullptr || g_write_string == nullptr) {
        return kStatusUnknownTransaction;
    }
    if (g_write_int32(output, kStatusOk) != kStatusOk) return -22;
    const int32_t length = static_cast<int32_t>(g_payload.size());
    return g_write_string(output, g_payload.c_str(), length) == kStatusOk ? kStatusOk : -22;
}

void resolve_binder_api() {
    void *library = dlopen("libbinder_ndk.so", RTLD_NOW | RTLD_LOCAL);
    if (library == nullptr) return;
    g_class_define = reinterpret_cast<BinderClassDefine>(
            dlsym(library, "AIBinder_Class_define"));
    g_binder_new = reinterpret_cast<BinderNew>(dlsym(library, "AIBinder_new"));
    g_write_int32 = reinterpret_cast<ParcelWriteInt32>(
            dlsym(library, "AParcel_writeInt32"));
    g_write_string = reinterpret_cast<ParcelWriteString>(
            dlsym(library, "AParcel_writeString"));
    if (g_class_define != nullptr) {
        g_probe_class = g_class_define(kDescriptor, binder_on_create, binder_on_destroy,
                                       binder_on_transact);
    }
}

AIBinder *native_service_on_bind(ANativeService *, uint64_t, const char *, const char *) {
    if (g_binder_new == nullptr || g_probe_class == nullptr) return nullptr;
    return g_binder_new(g_probe_class, nullptr);
}

}  // namespace

extern "C" __attribute__((visibility("default"))) void ANativeService_onCreate(
        ANativeService *service) {
    g_payload = collect_payload();
    resolve_binder_api();

    void *library = dlopen("libandroid.so", RTLD_NOW | RTLD_LOCAL);
    if (library == nullptr) return;
    void *symbol = dlsym(library, "ANativeService_setOnBindCallback");
    if (symbol == nullptr) return;
    using SetOnBindCallback = void (*)(ANativeService *, ANativeService_onBindCallback);
    reinterpret_cast<SetOnBindCallback>(symbol)(service, native_service_on_bind);
}

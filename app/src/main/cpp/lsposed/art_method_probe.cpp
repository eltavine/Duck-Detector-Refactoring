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

#include <jni.h>

#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace {

    struct MapEntry {
        uintptr_t start = 0;
        uintptr_t end = 0;
        std::string perms;
        std::string path;

        bool contains(uintptr_t value) const {
            return value >= start && value < end;
        }

        bool executable() const {
            return perms.size() > 2 && perms[2] == 'x';
        }
    };

    std::string trim_copy(std::string value) {
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())) != 0) {
            value.erase(value.begin());
        }
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0) {
            value.pop_back();
        }
        return value;
    }

    std::string lowercase_copy(std::string value) {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        });
        return value;
    }

    bool contains_ignore_case(const std::string &haystack, const std::string &needle) {
        return lowercase_copy(haystack).find(lowercase_copy(needle)) != std::string::npos;
    }

    std::string escape_value(const std::string &value) {
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

    std::string read_text_file(const char *path, size_t max_size) {
        const int fd = static_cast<int>(syscall(__NR_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC));
        if (fd < 0) {
            return "";
        }

        std::string content;
        content.reserve(8192);
        char buffer[4096];
        ssize_t bytes_read = 0;
        while ((bytes_read = syscall(__NR_read, fd, buffer, sizeof(buffer))) > 0) {
            content.append(buffer, static_cast<size_t>(bytes_read));
            if (content.size() >= max_size) {
                break;
            }
        }
        syscall(__NR_close, fd);
        return content;
    }

    bool parse_hex_range(const std::string &range, uintptr_t &start, uintptr_t &end) {
        const size_t dash = range.find('-');
        if (dash == std::string::npos) {
            return false;
        }
        start = static_cast<uintptr_t>(std::strtoull(range.substr(0, dash).c_str(), nullptr, 16));
        end = static_cast<uintptr_t>(std::strtoull(range.substr(dash + 1).c_str(), nullptr, 16));
        return start != 0 && end > start;
    }

    std::vector<MapEntry> read_maps() {
        std::vector<MapEntry> entries;
        const std::string raw = read_text_file("/proc/self/maps", 512 * 1024);
        std::istringstream stream(raw);
        std::string line;
        while (std::getline(stream, line)) {
            std::istringstream line_stream(line);
            std::string range;
            std::string perms;
            std::string offset;
            std::string dev;
            std::string inode;
            if (!(line_stream >> range >> perms >> offset >> dev >> inode)) {
                continue;
            }

            uintptr_t start = 0;
            uintptr_t end = 0;
            if (!parse_hex_range(range, start, end)) {
                continue;
            }

            std::string path;
            std::getline(line_stream, path);
            entries.push_back(MapEntry{
                    .start = start,
                    .end = end,
                    .perms = perms,
                    .path = trim_copy(path),
            });
        }
        return entries;
    }

    const MapEntry *find_map(const std::vector<MapEntry> &maps, uintptr_t value) {
        for (const MapEntry &entry: maps) {
            if (entry.contains(value)) {
                return &entry;
            }
        }
        return nullptr;
    }

    std::string hex_value(uintptr_t value) {
        std::ostringstream out;
        out << "0x" << std::hex << std::nouppercase << value;
        return out.str();
    }

    std::string classify_region(const MapEntry &entry) {
        const std::string lower = lowercase_copy(entry.path);
        if (lower.empty() || lower.rfind("[anon:", 0) == 0 || lower.rfind("[anon_shmem:", 0) == 0) {
            if (lower.find("jit") != std::string::npos ||
                lower.find("dalvik") != std::string::npos) {
                return "JIT_CACHE";
            }
            return "ANON_EXEC";
        }
        if (lower.find("(deleted)") != std::string::npos) {
            return "DELETED_EXEC";
        }
        if (lower.find("memfd:") != std::string::npos) {
            if (lower.find("jit") != std::string::npos ||
                lower.find("dalvik") != std::string::npos) {
                return "JIT_CACHE";
            }
            return "MEMFD_EXEC";
        }
        if (lower.find("ashmem") != std::string::npos) {
            if (lower.find("jit") != std::string::npos ||
                lower.find("dalvik") != std::string::npos) {
                return "JIT_CACHE";
            }
            return "ASHMEM_EXEC";
        }
        if (lower.find("lsposed") != std::string::npos ||
            lower.find("xposed") != std::string::npos ||
            lower.find("lsplant") != std::string::npos ||
            lower.find("edxposed") != std::string::npos ||
            lower.find("riru") != std::string::npos ||
            lower.find("frida") != std::string::npos ||
            lower.find("substrate") != std::string::npos ||
            lower.find("zygisk") != std::string::npos ||
            lower.find("magisk") != std::string::npos ||
            lower.find("/data/adb/") != std::string::npos) {
            return "SUSPICIOUS_EXEC";
        }
        if (lower.find("/apex/com.android.art/") != std::string::npos ||
            lower.find("/apex/com.android.runtime/") != std::string::npos ||
            lower.find("/libart.so") != std::string::npos) {
            return "ART_RUNTIME";
        }
        if (lower.find("boot.oat") != std::string::npos ||
            lower.find("boot.art") != std::string::npos ||
            lower.find("/system/framework/") != std::string::npos) {
            return "BOOT_IMAGE";
        }
        if (lower.find("/oat/") != std::string::npos ||
            lower.find(".odex") != std::string::npos ||
            lower.find(".oat") != std::string::npos) {
            return "APP_OAT";
        }
        if (lower.find("jit-cache") != std::string::npos ||
            lower.find("dalvik-jit") != std::string::npos) {
            return "JIT_CACHE";
        }
        return "OTHER_EXEC";
    }

    bool suspicious_region(const std::string &kind) {
        return kind == "SUSPICIOUS_EXEC" ||
               kind == "DELETED_EXEC" ||
               kind == "MEMFD_EXEC" ||
               kind == "ASHMEM_EXEC" ||
               kind == "ANON_EXEC" ||
               kind == "OTHER_EXEC";
    }

    std::string jstring_to_string(JNIEnv *env, jstring value) {
        if (value == nullptr) {
            return "";
        }
        const char *chars = env->GetStringUTFChars(value, nullptr);
        if (chars == nullptr) {
            return "";
        }
        std::string result(chars);
        env->ReleaseStringUTFChars(value, chars);
        return result;
    }

    jstring to_jstring(JNIEnv *env, const std::string &value) {
        return env->NewStringUTF(value.c_str());
    }

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_lsposed_data_art_ArtMethodNativeBridge_nativeCollectSnapshot(
        JNIEnv *env,
        jobject,
        jobjectArray methods,
        jobjectArray labels
) {
    const std::vector<MapEntry> maps = read_maps();
    std::ostringstream output;
    output << "AVAILABLE=" << (!maps.empty() ? '1' : '0') << '\n';
    if (methods == nullptr || labels == nullptr || maps.empty()) {
        return to_jstring(env, output.str());
    }

    const jsize method_count = env->GetArrayLength(methods);
    const jsize label_count = env->GetArrayLength(labels);
    const jsize count = std::min(method_count, label_count);

    for (jsize index = 0; index < count; ++index) {
        jobject method = env->GetObjectArrayElement(methods, index);
        auto label_string = static_cast<jstring>(env->GetObjectArrayElement(labels, index));
        const std::string label = jstring_to_string(env, label_string);
        env->DeleteLocalRef(label_string);

        if (method == nullptr) {
            output << "METHOD=" << escape_value(label) << "\t0x0\t0\n";
            continue;
        }

        jmethodID method_id = env->FromReflectedMethod(method);
        env->DeleteLocalRef(method);
        const auto art_method = reinterpret_cast<uintptr_t>(method_id);
        const MapEntry *art_map = find_map(maps, art_method);
        const uintptr_t max_end = art_map != nullptr ? art_map->end : art_method;
        const size_t readable_bytes = art_method < max_end
                                      ? std::min<size_t>(160U, static_cast<size_t>(max_end - art_method))
                                      : 0U;

        std::vector<std::string> candidate_lines;
        if (readable_bytes >= sizeof(uintptr_t)) {
            for (size_t offset = 0; offset + sizeof(uintptr_t) <= readable_bytes;
                 offset += sizeof(uintptr_t)) {
                const auto *slot = reinterpret_cast<const uintptr_t *>(art_method + offset);
                const uintptr_t target = *slot;
                const MapEntry *target_map = find_map(maps, target);
                if (target_map == nullptr || !target_map->executable()) {
                    continue;
                }
                const std::string kind = classify_region(*target_map);
                const bool suspicious = suspicious_region(kind);
                std::ostringstream detail;
                detail << "ArtMethod+" << offset << " -> "
                       << kind << " " << target_map->perms << " "
                       << hex_value(target - target_map->start);
                std::ostringstream line;
                line << "CANDIDATE="
                     << escape_value(label) << '\t'
                     << offset << '\t'
                     << hex_value(target) << '\t'
                     << kind << '\t'
                     << hex_value(target_map->start) << '\t'
                     << hex_value(target - target_map->start) << '\t'
                     << target_map->perms << '\t'
                     << (suspicious ? '1' : '0') << '\t'
                     << escape_value(target_map->path) << '\t'
                     << escape_value(detail.str())
                     << '\n';
                candidate_lines.push_back(line.str());
            }
        }

        output << "METHOD="
               << escape_value(label) << '\t'
               << hex_value(art_method) << '\t'
               << candidate_lines.size() << '\n';
        for (const std::string &line: candidate_lines) {
            output << line;
        }
    }

    return to_jstring(env, output.str());
}

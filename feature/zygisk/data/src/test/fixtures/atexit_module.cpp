// SPDX-License-Identifier: Apache-2.0
// Optional AVD-only fixture, built against the public Zygisk module SDK; never shipped in the app.
#include <sys/types.h>
#include <zygisk.hpp>
#include <android/dlext.h>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

namespace {
    class ExitHandlerFixture : public zygisk::ModuleBase {
    public:
        void onLoad(zygisk::Api *api, JNIEnv *environment) override {
            api_ = api;
            environment_ = environment;
        }

        void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
            const char *name = environment_->GetStringUTFChars(args->nice_name, nullptr);
            if (name != nullptr) {
                if (std::strcmp(name, "com.eltavine.duckdetector") == 0) {
                    load_payload();
                }
                environment_->ReleaseStringUTFChars(args->nice_name, name);
            }
        }

    private:
        void load_payload() {
            const int directory = api_->getModuleDir();
            if (directory < 0) return;
            const int source = openat(directory, "callback_payload.so", O_RDONLY | O_CLOEXEC);
            close(directory);
            if (source < 0) return;
            const int image = memfd_create("duck-atexit-fixture", MFD_CLOEXEC);
            if (image < 0) { close(source); return; }
            char bytes[4096];
            ssize_t size = 0;
            bool copied = true;
            while ((size = read(source, bytes, sizeof(bytes))) > 0) {
                if (write(image, bytes, size) != size) { copied = false; break; }
            }
            close(source);
            if (copied && size == 0) {
                android_dlextinfo options{};
                options.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
                options.library_fd = image;
                // Keep the handle resident until process exit so its callback remains valid.
                payload_ = android_dlopen_ext("duck-atexit-payload.so", RTLD_NOW, &options);
            }
            close(image);
        }

        zygisk::Api *api_ = nullptr;
        JNIEnv *environment_ = nullptr;
        void *payload_ = nullptr;
    };
}

REGISTER_ZYGISK_MODULE(ExitHandlerFixture)

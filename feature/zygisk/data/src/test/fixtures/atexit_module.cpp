// SPDX-License-Identifier: Apache-2.0
// Optional AVD-only fixture, built against the public Zygisk module SDK; never shipped in the app.
#include <sys/types.h>
#include <zygisk.hpp>
#include <android/dlext.h>
#include <android/log.h>
#include <payload_bytes.h>
#include <cstring>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>

namespace {
    class ExitHandlerFixture : public zygisk::ModuleBase {
    public:
        void onLoad(zygisk::Api *, JNIEnv *environment) override { environment_ = environment; }

        void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
            const char *name = environment_->GetStringUTFChars(args->nice_name, nullptr);
            if (name != nullptr) {
                if (std::strcmp(name, "com.eltavine.duckdetector") == 0) {
                    __android_log_write(ANDROID_LOG_INFO, "AtexitFixture", "Target pre-specialize callback reached.");
                    load_payload();
                }
                environment_->ReleaseStringUTFChars(args->nice_name, name);
            }
        }

    private:
        void load_payload() {
            const int image = memfd_create("duck-atexit-fixture", MFD_CLOEXEC);
            if (image < 0) return;
            if (write(image, kPayload, sizeof(kPayload)) == static_cast<ssize_t>(sizeof(kPayload))) {
                android_dlextinfo options{};
                options.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
                options.library_fd = image;
                // Keep the handle resident until process exit so its callback remains valid.
                payload_ = android_dlopen_ext("duck-atexit-payload.so", RTLD_NOW, &options);
                __android_log_print(ANDROID_LOG_INFO, "AtexitFixture", "Payload loaded=%d: %s",
                                    payload_ != nullptr, payload_ == nullptr ? dlerror() : "resident");
            }
            close(image);
        }

        JNIEnv *environment_ = nullptr;
        void *payload_ = nullptr;
    };
}

REGISTER_ZYGISK_MODULE(ExitHandlerFixture)

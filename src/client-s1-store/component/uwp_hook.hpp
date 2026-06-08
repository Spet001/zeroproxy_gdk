#pragma once
#include "common_core.hpp"
#include <string>
#include <unordered_set>
#include <format>
#include <cstdint>
#include "utils/hook.hpp"
#include "utils/nt.hpp"
#include "logger/logger.hpp"
#include "engine/uwp/IStoreImpl6.hpp"

namespace uwp {
    struct XVersion {
        uint16_t major;
        uint16_t minor;
        uint16_t build;
        uint16_t revision;
    };

    struct XPackageDetails {
        const char* packageIdentifier;
        XVersion    version;
        uint32_t    kind;
        uint8_t     _pad_kind[4];
        const char* displayName;
        const char* description;
        const char* publisher;
        const char* storeId;
        bool        installing;
        uint8_t     _pad0[3];
        uint32_t    index;
        uint32_t    count;
        bool        ageRestricted;
        uint8_t     _pad1[3];
        const char* titleID;
    };
    static_assert(sizeof(XPackageDetails) == 80, "XPackageDetails size mismatch");

    inline void* get_vt_function(void* class_ptr, std::size_t index) {
        struct vt_cls { void** vftable_; };
        return PTR_AS(vt_cls*, class_ptr)->vftable_[index];
    }

    inline std::unordered_set<uwp::XAsyncBlock*> fake_async_blocks;

    inline DWORD WINAPI fake_async_thread(LPVOID param) {
        uwp::XAsyncBlock* async = (uwp::XAsyncBlock*)param;
        Sleep(1);
        void(*cb)(uwp::XAsyncBlock*) = *(void(**)(uwp::XAsyncBlock*))((uint8_t*)async + 16);
        if (cb) cb(async);
        return 0;
    }

    namespace x_package {
        inline std::unordered_set<void*> fake_mount_handles;

        inline utils::hook::detour x_package_mount_hook;
        inline utils::hook::detour x_package_mount_with_ui_result_hook;
        inline utils::hook::detour x_package_get_mount_path_size_hook;
        inline utils::hook::detour x_package_get_mount_path_hook;
        inline utils::hook::detour x_package_close_mount_handle_hook;
        inline utils::hook::detour x_package_enumerate_packages_v8_hook;
        inline utils::hook::detour x_package_mount_with_ui_async_hook;

        struct PkgEnumCtx {
            void* orig_cb;
            void* orig_ctx;
        };

        inline bool __stdcall hook_pkg_enum_callback(void* ctx, const XPackageDetails* details) {
            if (!ctx || !details) return true;
            PkgEnumCtx* c = reinterpret_cast<PkgEnumCtx*>(ctx);
            typedef bool(__stdcall* PkgEnumCb_t)(void*, const XPackageDetails*);
            PkgEnumCb_t orig = reinterpret_cast<PkgEnumCb_t>(c->orig_cb);
            
            if (details && details->kind == 1 && details->storeId && details->packageIdentifier) {
                LOG("UWP", INFO, "Intercepted real package enum! ID: {}, StoreID: {}", details->packageIdentifier, details->storeId);
            }
            return orig(c->orig_ctx, details);
        }

        inline HRESULT x_package_enumerate_packages_v8_stub(void* _this, uint32_t kind, uint32_t scope, void* ctx, void* cb) {
            LOG("UWP", INFO, "XPackageEnumeratePackages called!");
            auto func = reinterpret_cast<HRESULT(__stdcall*)(void*, uint32_t, uint32_t, void*, void*)>(x_package_enumerate_packages_v8_hook.get_original());
            PkgEnumCtx wrapper_ctx = { cb, ctx };
            void* call_cb = cb ? (void*)&hook_pkg_enum_callback : nullptr;
            void* call_ctx = cb ? (void*)&wrapper_ctx : ctx;
            
            HRESULT hr = func(_this, kind, scope, call_ctx, call_cb);

            if (cb && SUCCEEDED(hr)) {
                // If the user manually placed DLC files in zone/dlc but didn't download them from the MS Store,
                // the real XPackageEnumeratePackages will return 0 packages. If 0 packages are returned,
                // the game will never call XPackageMountWithUiAsync, and thus will never read the zone/dlc folder.
                // We inject a fake package here to force the game to attempt a mount!
                XPackageDetails fake_details = {};
                fake_details.packageIdentifier = "AdvancedWarfare.DLC.Mock";
                fake_details.storeId = "AdvancedWarfare.DLC.Mock";
                fake_details.kind = 1; // Content
                fake_details.displayName = "Advanced Warfare Fake DLC";
                
                typedef bool(__stdcall* PkgEnumCb_t)(void*, const XPackageDetails*);
                PkgEnumCb_t orig_cb = reinterpret_cast<PkgEnumCb_t>(cb);
                orig_cb(ctx, &fake_details);
                LOG("UWP", INFO, "Injected fake DLC package into XPackageEnumeratePackages!");
            }

            return hr;
        }

        inline HRESULT x_package_mount_stub(void* _this, const char* package_identifier, void** out_handle) {
            LOG("UWP", INFO, "XPackageMount called for package: {}", package_identifier ? package_identifier : "null");
            if (out_handle) {
                void* fake = malloc(0x10);
                memset(fake, 0, 0x10);
                *out_handle = fake;
                fake_mount_handles.insert(fake);
                LOG("UWP", INFO, "Faked XPackageMount! Injected fake mount handle.");
            }
            return S_OK;
        }

        inline HRESULT x_package_mount_with_ui_async_stub(void* _this, const char* package_identifier, uwp::XAsyncBlock* async) {
            LOG("UWP", INFO, "XPackageMountWithUiAsync called for package: {}", package_identifier ? package_identifier : "null");
            fake_async_blocks.insert(async);
            HANDLE h = CreateThread(nullptr, 0, fake_async_thread, async, 0, nullptr);
            if (h) CloseHandle(h);
            return S_OK;
        }

        inline HRESULT x_package_mount_with_ui_result_stub(void* _this, uwp::XAsyncBlock* async, void** out_handle) {
            if (fake_async_blocks.contains(async)) {
                fake_async_blocks.erase(async);
                if (out_handle) {
                    void* fake = malloc(0x10);
                    memset(fake, 0, 0x10);
                    *out_handle = fake;
                    fake_mount_handles.insert(fake);
                    LOG("UWP", INFO, "Faked XPackageMountWithUiResult! Injected fake mount handle.");
                }
                return S_OK;
            }
            auto func = reinterpret_cast<HRESULT(__stdcall*)(void*, void*, void**)>(x_package_mount_with_ui_result_hook.get_original());
            return func(_this, async, out_handle);
        }

        inline HRESULT x_package_get_mount_path_size_stub(void* _this, void* handle, uint64_t* out_size) {
            if (fake_mount_handles.contains(handle)) {
                if (out_size) {
                    char path[MAX_PATH];
                    GetModuleFileNameA(nullptr, path, MAX_PATH);
                    std::string dir(path);
                    auto pos = dir.find_last_of("\\/");
                    dir = (pos != std::string::npos) ? dir.substr(0, pos) : dir;
                    dir += "\\"; // Always use base game folder for AW
                    *out_size = dir.size() + 1;
                    LOG("UWP", INFO, "Faked XPackageGetMountPathSize to: {}", *out_size);
                }
                return S_OK;
            }
            auto func = reinterpret_cast<HRESULT(__stdcall*)(void*, void*, uint64_t*)>(x_package_get_mount_path_size_hook.get_original());
            return func(_this, handle, out_size);
        }

        inline HRESULT x_package_get_mount_path_stub(void* _this, void* handle, uint64_t out_size, char* out_buf) {
            if (fake_mount_handles.contains(handle)) {
                if (out_buf) {
                    char path[MAX_PATH];
                    GetModuleFileNameA(nullptr, path, MAX_PATH);
                    std::string dir(path);
                    auto pos = dir.find_last_of("\\/");
                    dir = (pos != std::string::npos) ? dir.substr(0, pos) : dir;
                    dir += "\\"; // Always use base game folder for AW
                    strncpy_s(out_buf, out_size, dir.c_str(), _TRUNCATE);
                    LOG("UWP", INFO, "Faked XPackageGetMountPath to: {}", out_buf);
                }
                return S_OK;
            }
            auto func = reinterpret_cast<HRESULT(__stdcall*)(void*, void*, uint64_t, char*)>(x_package_get_mount_path_hook.get_original());
            return func(_this, handle, out_size, out_buf);
        }

        inline void x_package_close_mount_handle_stub(void* _this, void* handle) {
            if (fake_mount_handles.contains(handle)) {
                fake_mount_handles.erase(handle);
                free(handle);
            }
        }
    }

    namespace x_store {
        inline utils::hook::detour x_store_enumerate_products_query_hook;
        inline utils::hook::detour x_store_query_entitled_products_async_hook;
        inline utils::hook::detour x_store_acquire_license_for_package_async_hook;
        inline utils::hook::detour x_store_acquire_license_for_package_result_hook;
        inline utils::hook::detour x_store_license_is_valid_hook;
        inline utils::hook::detour x_store_close_license_handle_hook;
        inline utils::hook::detour x_store_query_game_license_result_hook;
        inline utils::hook::detour x_store_acquire_license_for_durables_async_hook;
        inline utils::hook::detour x_store_acquire_license_for_durables_result_hook;

        inline HRESULT x_store_acquire_license_for_durables_async_stub(uwp::IStoreImpl1* _this, const uwp::XStoreContextHandle store_context_handle, const char* store_id, uwp::XAsyncBlock* async) {
            LOG("UWP", INFO, "XStoreAcquireLicenseForDurablesAsync called for StoreId: {}", store_id ? store_id : "null");
            auto func = reinterpret_cast<HRESULT(__stdcall*)(void*, void*, const char*, void*)>(x_store_acquire_license_for_durables_async_hook.get_original());
            HRESULT hr = func(_this, store_context_handle, store_id, async);
            if (FAILED(hr)) {
                LOG("UWP", INFO, "Synchronous failure! Falling back to FAKE license acquisition for Durables.");
                fake_async_blocks.insert(async);
                HANDLE h = CreateThread(nullptr, 0, fake_async_thread, async, 0, nullptr);
                if (h) CloseHandle(h);
                return S_OK;
            }
            return hr;
        }

        inline HRESULT x_store_acquire_license_for_durables_result_stub(uwp::IStoreImpl1* _this, uwp::XAsyncBlock* async, void** out_license) {
            if (fake_async_blocks.contains(async)) {
                fake_async_blocks.erase(async);
                if (out_license) {
                    void* fake = malloc(0x30);
                    memset(fake, 0, 0x30);
                    ((uint8_t*)fake)[0x18] = 1; // OFF_LICENSE_VALID
                    *out_license = fake;
                }
                return S_OK;
            }
            auto func = reinterpret_cast<HRESULT(__stdcall*)(void*, void*, void**)>(x_store_acquire_license_for_durables_result_hook.get_original());
            HRESULT hr = func(_this, async, out_license);
            if (SUCCEEDED(hr) && out_license && *out_license) {
                ((uint8_t*)*out_license)[0x18] = 1; // Force license valid
            } else if (FAILED(hr) && out_license) {
                void* fake = malloc(0x30);
                memset(fake, 0, 0x30);
                ((uint8_t*)fake)[0x18] = 1; // OFF_LICENSE_VALID
                *out_license = fake;
                hr = S_OK;
            }
            return hr;
        }

        inline HRESULT x_store_acquire_license_for_package_async_stub(uwp::IStoreImpl1* _this, const uwp::XStoreContextHandle store_context_handle, const char* package_identifier, uwp::XAsyncBlock* async) {
            LOG("UWP", INFO, "XStoreAcquireLicenseForPackageAsync called for package: {}", package_identifier ? package_identifier : "null");
            fake_async_blocks.insert(async);
            HANDLE h = CreateThread(nullptr, 0, fake_async_thread, async, 0, nullptr);
            if (h) CloseHandle(h);
            return S_OK;
        }

        struct ProductsCbCtx {
            bool(*userCb)(const uwp::XStoreProduct*, void*) = nullptr;
            void* userCtx = nullptr;
        };

        inline void PatchProductSkuData(uint8_t* product) {
            uint32_t skuCount = *(uint32_t*)(product + 160);
            uint8_t* skuArr   = *(uint8_t**)(product + 168);
            if (!skuArr || skuCount == 0) return;
            for (uint32_t i = 0; i < skuCount && i < 64; i++) {
                uint8_t* sku = skuArr + (size_t)i * 0x110;
                sku[121]  = 1;
                sku[120]  = 0;
                *(int64_t*)(sku + 128)  = 133484064000000000LL;
                *(int64_t*)(sku + 136)  = 133484064000000000LL;
                *(int64_t*)(sku + 144)  = 0x7FFFFFFFFFFFFFFELL;
                sku[152]                 = 0;
                *(uint32_t*)(sku + 156) = 0;
                *(uint32_t*)(sku + 160)  = 1;
            }
        }

        inline bool hook_get_products_callback(const uwp::XStoreProduct* product, void* ctx) {
            auto* p = const_cast<uwp::XStoreProduct*>(product);
            p->has_digital_download_ = true;
            p->is_in_user_collection_ = true;
            uint8_t* prodBytes = reinterpret_cast<uint8_t*>(p);
            uint32_t skuCount = *(uint32_t*)(prodBytes + 0xA0);
            uint8_t* skuArr = *(uint8_t**)(prodBytes + 0xA8);
            if (skuArr && skuCount > 0) {
                for (uint32_t i = 0; i < skuCount && i < 64; i++) {
                    uint8_t* sku = skuArr + (size_t)i * 0x110;
                    sku[121]  = 1;
                    sku[120]  = 0;
                    *(int64_t*)(sku + 128)  = 133484064000000000LL;
                    *(int64_t*)(sku + 136)  = 133484064000000000LL;
                    *(int64_t*)(sku + 144)  = 0x7FFFFFFFFFFFFFFELL;
                    sku[152]                 = 0;
                    *(uint32_t*)(sku + 156)  = 0;
                    *(uint32_t*)(sku + 160)  = 1;
                }
            }
            auto* c = reinterpret_cast<ProductsCbCtx*>(ctx);
            LOG("UWP", INFO, "XStoreProduct patched! title={} storeId={}", p->title_ ? p->title_ : "null", p->store_id_ ? p->store_id_ : "null");
            return c->userCb ? c->userCb(product, c->userCtx) : true;
        }

        inline HRESULT x_store_enumerate_products_query_stub(uwp::IStoreImpl1* _this, const uwp::XStoreProductQueryHandle product_query_handle, void* context, bool(*callback)(const uwp::XStoreProduct*, void*)) {
            LOG("UWP", INFO, "XStoreEnumerateProductsQuery called!");
            ProductsCbCtx cbCtx;
            cbCtx.userCb = callback;
            cbCtx.userCtx = context;
            void* callCtx = callback ? (void*)&cbCtx : context;
            void* callCb  = callback ? (void*)&hook_get_products_callback : nullptr;

            HRESULT hr = x_store_enumerate_products_query_hook.invoke<HRESULT>(_this, product_query_handle, callCtx, callCb);

            if (!callback && hr == S_OK && product_query_handle) {
                auto* base = *(uint8_t**)((uint8_t*)product_query_handle + 24);
                auto* end  = *(uint8_t**)((uint8_t*)product_query_handle + 32);
                for (uint8_t* p = base; base && p < end; p += 208) {
                    if (!p[145]) { p[145] = 1; }
                    if (!p[144]) { p[144] = 1; }
                    PatchProductSkuData(p);
                }
            }
            return hr;
        }

        inline HRESULT x_store_query_entitled_products_async_stub(uwp::IStoreImpl1* _this, const uwp::XStoreContextHandle store_context_handle, uwp::XStoreProductKind product_kinds, std::uint32_t max_items_to_retrieve_per_page, uwp::XAsyncBlock* async) {
            uint32_t kinds = (uint32_t)product_kinds;
            LOG("UWP", INFO, "XStoreQueryEntitledProductsAsync called with product_kinds: {}", kinds);
            
            // XStoreProductKind::Game is 0x04. If the game is querying for its own base license, we MUST let it through to the real API.
            // If we redirect it to QueryAssociatedProductsAsync, it will return nothing (a game is not an associated product of itself),
            // causing the game to fail its base entitlement check and disable DLCs.
            if ((kinds & 4) != 0) {
                LOG("UWP", INFO, "Letting Game (0x04) entitlement query go to real API...");
                auto func = reinterpret_cast<HRESULT(__stdcall*)(void*, void*, uint32_t, uint32_t, void*)>(x_store_query_entitled_products_async_hook.get_original());
                return func(_this, (void*)store_context_handle, kinds, max_items_to_retrieve_per_page, async);
            }

            LOG("UWP", INFO, "Intercepted XStoreQueryEntitledProductsAsync! Redirecting to XStoreQueryAssociatedProductsAsync...");
            auto func = get_vt_function(_this, 5); // QueryAssociatedProductsAsync
            typedef HRESULT(__stdcall* QueryAssociatedT)(uwp::IStoreImpl1*, uwp::XStoreContextHandle, uwp::XStoreProductKind, std::uint32_t, uwp::XAsyncBlock*);
            return ((QueryAssociatedT)func)(_this, store_context_handle, product_kinds, max_items_to_retrieve_per_page, async);
        }

        inline HRESULT x_store_acquire_license_for_package_result_stub(uwp::IStoreImpl1* _this, uwp::XAsyncBlock* async, void** out_license) {
            if (fake_async_blocks.contains(async)) {
                fake_async_blocks.erase(async);
                if (out_license) {
                    void* fake = malloc(0x30);
                    memset(fake, 0, 0x30);
                    ((uint8_t*)fake)[0x18] = 1;
                    *out_license = fake;
                }
                return S_OK;
            }
            auto func = reinterpret_cast<HRESULT(__stdcall*)(void*, void*, void**)>(x_store_acquire_license_for_package_result_hook.get_original());
            HRESULT hr = func(_this, async, out_license);
            if (SUCCEEDED(hr) && out_license && *out_license) {
                ((uint8_t*)*out_license)[0x18] = 1;
            } else if (FAILED(hr) && out_license) {
                void* fake = malloc(0x30);
                memset(fake, 0, 0x30);
                ((uint8_t*)fake)[0x18] = 1;
                *out_license = fake;
                hr = S_OK;
            }
            return hr;
        }

        inline HRESULT x_store_license_is_valid_stub(void* _this, void* license) {
            if (license) {
                uint8_t* ptr = reinterpret_cast<uint8_t*>(license);
                if (ptr[0x18] == 1) { return 1; }
            }
            auto func = reinterpret_cast<HRESULT(__stdcall*)(void*, void*)>(x_store_license_is_valid_hook.get_original());
            return func(_this, license);
        }

        inline void x_store_close_license_handle_stub(uwp::IStoreImpl1* _this, void* handle) {
            if (handle) { free(handle); }
        }

        inline HRESULT x_store_query_game_license_result_stub(uwp::IStoreImpl1* _this, uwp::XAsyncBlock* async, uwp::XStoreGameLicense* license) {
            x_store_query_game_license_result_hook.invoke<HRESULT>(_this, async, license);
            license->is_active_ = true;
            license->is_disc_license_ = false;
            license->is_trial_ = false;
            return S_OK;
        }
    }

    inline utils::hook::detour query_api_impl_hook;

    inline std::string guid_to_string(GUID guid) {
        return std::format("{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", guid.Data1, guid.Data2, guid.Data3,
            guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    }

    inline bool is_target_api(GUID guid_first, GUID guid_second, const std::string& guid_first_target, const std::string& guid_second_target) {
        return guid_to_string(guid_first) == guid_first_target && guid_to_string(guid_second) == guid_second_target;
    }

    inline HRESULT query_api_impl_stub(GUID* first, GUID* second, void** api_out) {
        auto res = query_api_impl_hook.invoke<HRESULT>(first, second, api_out);

        if (first != nullptr && second != nullptr && res >= 0 && api_out && *api_out) {
            static bool hooked_pkg_vt = false;
            static bool hooked_store_vt = false;

            if (!hooked_pkg_vt && is_target_api(*first, *second, "af406016-e850-4aa8-a88d-2f3dcb9dac7e", "e2a4734b-2f4a-456d-aa8f-d065e04fb209")) {
                LOG("UWP", INFO, "Game requested XPackage API! Hooking XPackage interfaces...");
                x_package::x_package_enumerate_packages_v8_hook.create(get_vt_function(*api_out, 39), x_package::x_package_enumerate_packages_v8_stub);
                x_package::x_package_mount_hook.create(get_vt_function(*api_out, 36), x_package::x_package_mount_stub);
                x_package::x_package_mount_with_ui_async_hook.create(get_vt_function(*api_out, 37), x_package::x_package_mount_with_ui_async_stub);
                x_package::x_package_mount_with_ui_result_hook.create(get_vt_function(*api_out, 38), x_package::x_package_mount_with_ui_result_stub);
                x_package::x_package_get_mount_path_size_hook.create(get_vt_function(*api_out, 24), x_package::x_package_get_mount_path_size_stub);
                x_package::x_package_get_mount_path_hook.create(get_vt_function(*api_out, 25), x_package::x_package_get_mount_path_stub);
                x_package::x_package_close_mount_handle_hook.create(get_vt_function(*api_out, 26), x_package::x_package_close_mount_handle_stub);
                hooked_pkg_vt = true;
            }

            if (!hooked_store_vt && is_target_api(*first, *second, "0dd112ac-7c24-448c-b92b-3960fb5bd30c", "5c48dedf-0b67-4492-a4b5-6829b8e796e1")) {
                LOG("UWP", INFO, "Game requested XStore API! Hooking XStore interfaces...");
                x_store::x_store_query_entitled_products_async_hook.create(get_vt_function(*api_out, 9), x_store::x_store_query_entitled_products_async_stub);
                x_store::x_store_enumerate_products_query_hook.create(get_vt_function(*api_out, 15), x_store::x_store_enumerate_products_query_stub);
                x_store::x_store_acquire_license_for_package_async_hook.create(get_vt_function(*api_out, 20), x_store::x_store_acquire_license_for_package_async_stub);
                x_store::x_store_acquire_license_for_package_result_hook.create(get_vt_function(*api_out, 21), x_store::x_store_acquire_license_for_package_result_stub);
                x_store::x_store_license_is_valid_hook.create(get_vt_function(*api_out, 22), x_store::x_store_license_is_valid_stub);
                x_store::x_store_close_license_handle_hook.create(get_vt_function(*api_out, 23), x_store::x_store_close_license_handle_stub);
                x_store::x_store_query_game_license_result_hook.create(get_vt_function(*api_out, 29), x_store::x_store_query_game_license_result_stub);
                x_store::x_store_acquire_license_for_durables_async_hook.create(get_vt_function(*api_out, 30), x_store::x_store_acquire_license_for_durables_async_stub);
                x_store::x_store_acquire_license_for_durables_result_hook.create(get_vt_function(*api_out, 31), x_store::x_store_acquire_license_for_durables_result_stub);
                hooked_store_vt = true;
            }
        }
        return res;
    }

    inline void init_standalone_hooks() {
        static bool is_query_api_hooked = false;
        if (is_query_api_hooked) return;

        LOG("UWP", INFO, "Waiting to hook QueryApiImpl...");
        utils::nt::library lib("xgameruntime.dll");
        if (!lib.is_valid()) {
            LOG("UWP", INFO, "Failed to find xgameruntime.dll!");
            return;
        }

        auto query_api_impl = lib.get_proc<FARPROC>("QueryApiImpl");
        if (!query_api_impl) {
            LOG("UWP", INFO, "Failed to find QueryApiImpl!");
            return;
        }

        query_api_impl_hook.create(query_api_impl, query_api_impl_stub);
        is_query_api_hooked = true;
        LOG("UWP", INFO, "Successfully hooked QueryApiImpl!");
    }
}

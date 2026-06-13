#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>
#include <roapi.h>
#include <winstring.h>
#pragma comment(lib, "runtimeobject.lib")
#include <utils/nt.hpp>
#include <utils/hook.hpp>
#include <logger/logger.hpp>
#include <vector>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

namespace component::winrt_hook {
    
    typedef HRESULT(__stdcall* RoGetActivationFactory_t)(HSTRING, REFIID, void**);
    typedef HRESULT(__stdcall* RoActivateInstance_t)(HSTRING, IInspectable**);
    
    utils::hook::detour ro_activate_instance_hook;
    utils::hook::detour ro_get_activation_factory_hook;
    
    std::recursive_mutex global_mutex;
    std::unordered_map<void**, void**> custom_to_orig_vtable;

    typedef HRESULT(__stdcall* GenericMethod_t)(void*, void*, void*, void*, void*, void*, void*, void*, void*, void*, void*, void*);

    std::string ws2s(const std::wstring& wstr) {
        if (wstr.empty()) return std::string();
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
        std::string strTo(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
        return strTo;
    }

    bool safe_read_ptr(void* ptr, void** out) {
        if (!ptr || !out) return false;
        bool success = false;
        __try { *out = *(void**)ptr; success = true; } __except(1) { success = false; }
        return success;
    }

    int get_vtable_size(void** vtable) {
        int size = 0;
        MEMORY_BASIC_INFORMATION mbi;
        while (true) {
            if (IsBadReadPtr(&vtable[size], sizeof(void*))) break;
            void* func = vtable[size];
            if (!func) break;
            if (VirtualQuery(func, &mbi, sizeof(mbi)) == 0) break;
            if (!(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) break;
            size++;
        }
        return size;
    }

    void hook_vmt(void* obj, const std::string& name, auto setup_hooks) {
        if (!obj) return;
        std::lock_guard<std::recursive_mutex> lock(global_mutex);
        void** current_vtable = *(void***)obj;
        if (custom_to_orig_vtable.find(current_vtable) != custom_to_orig_vtable.end()) return;
        int size = get_vtable_size(current_vtable);
        if (size == 0) return;
        void** custom_vtable = new void*[size];
        memcpy(custom_vtable, current_vtable, size * sizeof(void*));
        auto hook_method = [&](int idx, void* stub) {
            if (idx >= 0 && idx < size) custom_vtable[idx] = stub;
        };
        setup_hooks(hook_method);
        custom_to_orig_vtable[custom_vtable] = current_vtable;
        *(void***)obj = custom_vtable;
    }

    GenericMethod_t get_orig_vmt_func(void* obj, int index) {
        void** custom_vtable = *(void***)obj;
        void** orig_vtable = nullptr;
        {
            std::lock_guard<std::recursive_mutex> lock(global_mutex);
            auto it = custom_to_orig_vtable.find(custom_vtable);
            if (it != custom_to_orig_vtable.end()) orig_vtable = it->second;
        }
        if (orig_vtable) return reinterpret_cast<GenericMethod_t>(orig_vtable[index]);
        return nullptr;
    }

    namespace Fakes {
        struct FakeStoreLicense {
            void** vtable;
            long ref_count;
            std::wstring store_id;
            FakeStoreLicense(const std::wstring& id) : ref_count(1), store_id(id) {
                static void* vt[] = {
                    (void*)+[](FakeStoreLicense* This, const IID& riid, void** ppv) -> HRESULT {
                        *ppv = This; return S_OK;
                    },
                    (void*)+[](FakeStoreLicense* This) -> ULONG { return 2; },
                    (void*)+[](FakeStoreLicense* This) -> ULONG { return 1; },
                    (void*)+[](FakeStoreLicense* This, ULONG* count, IID** iids) -> HRESULT { *count = 0; return S_OK; },
                    (void*)+[](FakeStoreLicense* This, HSTRING* name) -> HRESULT { return E_NOTIMPL; },
                    (void*)+[](FakeStoreLicense* This, int* trust) -> HRESULT { *trust = 0; return S_OK; },
                    // IStoreLicense
                    (void*)+[](FakeStoreLicense* This, HSTRING* value) -> HRESULT { 
                        return WindowsCreateString(This->store_id.c_str(), This->store_id.length(), value); 
                    }, // get_SkuStoreId
                    (void*)+[](FakeStoreLicense* This, boolean* value) -> HRESULT { *value = true; return S_OK; }, // get_IsActive
                    (void*)+[](FakeStoreLicense* This, void** value) -> HRESULT { return E_NOTIMPL; }, // get_ExpirationDate
                    (void*)+[](FakeStoreLicense* This, HSTRING* value) -> HRESULT { return E_NOTIMPL; }, // get_ExtendedJsonData
                    (void*)+[](FakeStoreLicense* This, HSTRING* value) -> HRESULT { return E_NOTIMPL; }  // get_InAppOfferToken
                };
                vtable = vt;
            }
        };

        struct FakeStoreProduct {
            void** vtable;
            long ref_count;
            std::wstring store_id;
            FakeStoreProduct(const std::wstring& id) : ref_count(1), store_id(id) {
                static void* vt[] = {
                    (void*)+[](FakeStoreProduct* This, const IID& riid, void** ppv) -> HRESULT {
                        *ppv = This; return S_OK;
                    },
                    (void*)+[](FakeStoreProduct* This) -> ULONG { return 2; },
                    (void*)+[](FakeStoreProduct* This) -> ULONG { return 1; },
                    (void*)+[](FakeStoreProduct* This, ULONG* count, IID** iids) -> HRESULT { *count = 0; return S_OK; },
                    (void*)+[](FakeStoreProduct* This, HSTRING* name) -> HRESULT { return E_NOTIMPL; },
                    (void*)+[](FakeStoreProduct* This, int* trust) -> HRESULT { *trust = 0; return S_OK; },
                    // IStoreProduct
                    (void*)+[](FakeStoreProduct* This, HSTRING* value) -> HRESULT { 
                        return WindowsCreateString(This->store_id.c_str(), This->store_id.length(), value); 
                    }, // StoreId
                    (void*)+[](FakeStoreProduct* This, HSTRING* value) -> HRESULT { return E_NOTIMPL; }, // Language
                    (void*)+[](FakeStoreProduct* This, HSTRING* value) -> HRESULT { 
                        std::wstring title = L"Fake Title";
                        return WindowsCreateString(title.c_str(), title.length(), value); 
                    }, // Title
                    (void*)+[](FakeStoreProduct* This, HSTRING* value) -> HRESULT { return E_NOTIMPL; }, // Description
                    (void*)+[](FakeStoreProduct* This, HSTRING* value) -> HRESULT { 
                        std::wstring kind = L"Durable";
                        return WindowsCreateString(kind.c_str(), kind.length(), value); 
                    }, // ProductKind
                    (void*)+[](FakeStoreProduct* This, boolean* value) -> HRESULT { *value = true; return S_OK; }, // HasDigitalDownload
                    (void*)+[](FakeStoreProduct* This, void** value) -> HRESULT { return E_NOTIMPL; }, // Keywords
                    (void*)+[](FakeStoreProduct* This, void** value) -> HRESULT { return E_NOTIMPL; }, // Images
                    (void*)+[](FakeStoreProduct* This, void** value) -> HRESULT { return E_NOTIMPL; }, // Videos
                    (void*)+[](FakeStoreProduct* This, void** value) -> HRESULT { return E_NOTIMPL; }, // Skus
                    (void*)+[](FakeStoreProduct* This, boolean* value) -> HRESULT { *value = true; return S_OK; }, // IsInUserCollection (SPOOFED!)
                    (void*)+[](FakeStoreProduct* This, void** value) -> HRESULT { return E_NOTIMPL; }, // Price
                    (void*)+[](FakeStoreProduct* This, HSTRING* value) -> HRESULT { return E_NOTIMPL; }, // ExtendedJsonData
                    (void*)+[](FakeStoreProduct* This, void** value) -> HRESULT { return E_NOTIMPL; }, // LinkUri
                    (void*)+[](FakeStoreProduct* This, void** value) -> HRESULT { return E_NOTIMPL; }, // RequestPurchaseAsync
                    (void*)+[](FakeStoreProduct* This, void* props, void** value) -> HRESULT { return E_NOTIMPL; }, // RequestPurchaseWithPurchasePropertiesAsync
                    (void*)+[](FakeStoreProduct* This, boolean* value) -> HRESULT { *value = false; return S_OK; } // IsTrial
                };
                vtable = vt;
            }
        };

        struct FakeKeyValuePair {
            void** vtable;
            long ref_count;
            std::wstring key;
            bool is_product;
            FakeKeyValuePair(const std::wstring& k, bool p) : ref_count(1), key(k), is_product(p) {
                static void* vt[] = {
                    (void*)+[](FakeKeyValuePair* This, const IID& riid, void** ppv) -> HRESULT { *ppv = This; return S_OK; },
                    (void*)+[](FakeKeyValuePair* This) -> ULONG { return 2; },
                    (void*)+[](FakeKeyValuePair* This) -> ULONG { return 1; },
                    (void*)+[](FakeKeyValuePair* This, ULONG* count, IID** iids) -> HRESULT { *count = 0; return S_OK; },
                    (void*)+[](FakeKeyValuePair* This, HSTRING* name) -> HRESULT { return E_NOTIMPL; },
                    (void*)+[](FakeKeyValuePair* This, int* trust) -> HRESULT { *trust = 0; return S_OK; },
                    // IKeyValuePair
                    (void*)+[](FakeKeyValuePair* This, HSTRING* k) -> HRESULT { 
                        LOG("WinRT", INFO, "FakeKeyValuePair::get_Key called!");
                        return WindowsCreateString(This->key.c_str(), This->key.length(), k); 
                    },
                    (void*)+[](FakeKeyValuePair* This, void** v) -> HRESULT { 
                        LOG("WinRT", INFO, "FakeKeyValuePair::get_Value called!");
                        if (This->is_product) *v = new FakeStoreProduct(This->key);
                        else *v = new FakeStoreLicense(This->key);
                        return S_OK; 
                    }
                };
                vtable = vt;
            }
        };

        struct FakeIterator {
            void** vtable;
            long ref_count;
            std::wstring key;
            bool is_product;
            bool done;

            FakeIterator(const std::wstring& k, bool p) : ref_count(1), key(k), is_product(p), done(false) {
                static void* vt[] = {
                    (void*)+[](FakeIterator* This, const IID& riid, void** ppv) -> HRESULT { *ppv = This; return S_OK; },
                    (void*)+[](FakeIterator* This) -> ULONG { return 2; },
                    (void*)+[](FakeIterator* This) -> ULONG { return 1; },
                    (void*)+[](FakeIterator* This, ULONG* count, IID** iids) -> HRESULT { *count = 0; return S_OK; },
                    (void*)+[](FakeIterator* This, HSTRING* name) -> HRESULT { return E_NOTIMPL; },
                    (void*)+[](FakeIterator* This, int* trust) -> HRESULT { *trust = 0; return S_OK; },
                    // IIterator
                    (void*)+[](FakeIterator* This, void** current) -> HRESULT { 
                        LOG("WinRT", INFO, "FakeIterator::get_Current called!");
                        if (This->done) return E_BOUNDS;
                        *current = new FakeKeyValuePair(This->key, This->is_product);
                        return S_OK; 
                    }, // get_Current
                    (void*)+[](FakeIterator* This, boolean* hasCurrent) -> HRESULT { 
                        LOG("WinRT", INFO, "FakeIterator::get_HasCurrent called!");
                        *hasCurrent = !This->done; return S_OK; 
                    }, // get_HasCurrent
                    (void*)+[](FakeIterator* This, boolean* hasCurrent) -> HRESULT { 
                        LOG("WinRT", INFO, "FakeIterator::MoveNext called!");
                        This->done = true; 
                        *hasCurrent = false; 
                        return S_OK; 
                    }, // MoveNext
                    (void*)+[](FakeIterator* This, unsigned int capacity, void** items, unsigned int* actual) -> HRESULT { *actual = 0; return S_OK; } // GetMany
                };
                vtable = vt;
            }
        };

        struct FakeMapView {
            void** vtable_map;
            void** vtable_iterable;
            long ref_count;
            bool is_product;
            std::wstring store_id;

            FakeMapView(bool product, const std::wstring& id) : ref_count(1), is_product(product), store_id(id) {
                static void* vt_map[] = {
                    (void*)+[](FakeMapView* This, const IID& riid, void** ppv) -> HRESULT { return This->QueryInterface(riid, ppv); },
                    (void*)+[](FakeMapView* This) -> ULONG { return 2; },
                    (void*)+[](FakeMapView* This) -> ULONG { return 1; },
                    (void*)+[](FakeMapView* This, ULONG* count, IID** iids) -> HRESULT { *count = 0; return S_OK; },
                    (void*)+[](FakeMapView* This, HSTRING* name) -> HRESULT { return E_NOTIMPL; },
                    (void*)+[](FakeMapView* This, int* trust) -> HRESULT { *trust = 0; return S_OK; },
                    // IMapView
                    (void*)+[](FakeMapView* This, HSTRING key, void** value) -> HRESULT { 
                        LOG("WinRT", INFO, "FakeMapView::Lookup called!");
                        if (This->is_product) *value = new FakeStoreProduct(This->store_id);
                        else *value = new FakeStoreLicense(This->store_id);
                        return S_OK; 
                    },
                    (void*)+[](FakeMapView* This, unsigned int* size) -> HRESULT { 
                        LOG("WinRT", INFO, "FakeMapView::Size called!");
                        *size = 1; 
                        return S_OK; 
                    },
                    (void*)+[](FakeMapView* This, HSTRING key, boolean* found) -> HRESULT { 
                        LOG("WinRT", INFO, "FakeMapView::HasKey called!");
                        *found = true; 
                        return S_OK; 
                    },
                    (void*)+[](FakeMapView* This, void** split) -> HRESULT { 
                        LOG("WinRT", INFO, "FakeMapView::Split called!");
                        return E_NOTIMPL; 
                    }
                };

                static void* vt_iterable[] = {
                    (void*)+[](void** ThisVtable, const IID& riid, void** ppv) -> HRESULT { 
                        FakeMapView* This = (FakeMapView*)((char*)ThisVtable - offsetof(FakeMapView, vtable_iterable));
                        return This->QueryInterface(riid, ppv); 
                    },
                    (void*)+[](void** ThisVtable) -> ULONG { return 2; },
                    (void*)+[](void** ThisVtable) -> ULONG { return 1; },
                    (void*)+[](void** ThisVtable, ULONG* count, IID** iids) -> HRESULT { *count = 0; return S_OK; },
                    (void*)+[](void** ThisVtable, HSTRING* name) -> HRESULT { return E_NOTIMPL; },
                    (void*)+[](void** ThisVtable, int* trust) -> HRESULT { *trust = 0; return S_OK; },
                    // IIterable
                    (void*)+[](void** ThisVtable, void** iterator) -> HRESULT { 
                        LOG("WinRT", INFO, "FakeMapView::First called!");
                        FakeMapView* This = (FakeMapView*)((char*)ThisVtable - offsetof(FakeMapView, vtable_iterable));
                        *iterator = new FakeIterator(This->store_id, This->is_product);
                        return S_OK; 
                    }
                };

                vtable_map = vt_map;
                vtable_iterable = vt_iterable;
            }

            HRESULT QueryInterface(const IID& riid, void** ppv) {
                if (!ppv) return E_POINTER;
                
                LOG("WinRT", INFO, "FakeMapView::QueryInterface called for IID: {:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                    riid.Data1, riid.Data2, riid.Data3, riid.Data4[0], riid.Data4[1], riid.Data4[2], riid.Data4[3], riid.Data4[4], riid.Data4[5], riid.Data4[6], riid.Data4[7]);

                static const IID IID_IUnknown = { 0x00000000, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
                if (memcmp(&riid, &IID_IUnknown, sizeof(IID)) == 0) {
                    *ppv = &vtable_map;
                    return S_OK;
                }

                static const IID IID_IInspectable = { 0xAF86E2E0, 0xB12D, 0x4C6A, { 0x9C, 0x5A, 0xD7, 0xAA, 0x65, 0x10, 0x1E, 0x90 } };
                if (memcmp(&riid, &IID_IInspectable, sizeof(IID)) == 0) {
                    *ppv = &vtable_map;
                    return S_OK;
                }

                static const IID IID_IIterable = { 0x00000000, 0x0000, 0x0000, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } }; // Needs proper GUID matching or fallback
                
                // IMarshal
                static const IID IID_IMarshal = { 0x00000003, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
                if (memcmp(&riid, &IID_IMarshal, sizeof(IID)) == 0) return E_NOINTERFACE;

                // IAgileObject
                static const IID IID_IAgileObject = { 0x94ea2b94, 0xe9cc, 0x49e0, { 0xc0, 0xff, 0xee, 0x64, 0xca, 0x8f, 0x5b, 0x90 } };
                if (memcmp(&riid, &IID_IAgileObject, sizeof(IID)) == 0) {
                    *ppv = &vtable_map;
                    return S_OK;
                }

                if (riid.Data4[0] == 0xC0 && riid.Data4[1] == 0x00 && riid.Data4[7] == 0x46) {
                    return E_NOINTERFACE;
                }

                // Assume IIterable if requested because IMapView inherits IIterable and the parameterized GUID varies
                // In actual WinRT, IIterable is the second interface
                // We will assume any unknown interface is IIterable for the map view
                *ppv = &vtable_iterable;
                return S_OK;
            }
        };

        struct FakeStoreProductPagedQueryResult {
            void** vtable;
            long ref_count;
            std::wstring store_id;
            FakeStoreProductPagedQueryResult(const std::wstring& id) : ref_count(1), store_id(id) {
                static void* vt[] = {
                    (void*)+[](FakeStoreProductPagedQueryResult* This, const IID& riid, void** ppv) -> HRESULT {
                        if (!ppv) return E_POINTER;
                        LOG("WinRT", INFO, "FakeStoreProductPagedQueryResult::QueryInterface called for IID: {:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                            riid.Data1, riid.Data2, riid.Data3, riid.Data4[0], riid.Data4[1], riid.Data4[2], riid.Data4[3], riid.Data4[4], riid.Data4[5], riid.Data4[6], riid.Data4[7]);

                        static const IID IID_IMarshal = { 0x00000003, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
                        if (memcmp(&riid, &IID_IMarshal, sizeof(IID)) == 0) return E_NOINTERFACE;

                        if (riid.Data4[0] == 0xC0 && riid.Data4[1] == 0x00 && riid.Data4[7] == 0x46 && riid.Data1 != 0 && riid.Data1 != 0xAF86E2E0) {
                            return E_NOINTERFACE;
                        }

                        *ppv = This; 
                        return S_OK;
                    },
                    (void*)+[](FakeStoreProductPagedQueryResult* This) -> ULONG { return 2; },
                    (void*)+[](FakeStoreProductPagedQueryResult* This) -> ULONG { return 1; },
                    (void*)+[](FakeStoreProductPagedQueryResult* This, ULONG* count, IID** iids) -> HRESULT { *count = 0; return S_OK; },
                    (void*)+[](FakeStoreProductPagedQueryResult* This, HSTRING* name) -> HRESULT { return E_NOTIMPL; },
                    (void*)+[](FakeStoreProductPagedQueryResult* This, int* trust) -> HRESULT { *trust = 0; return S_OK; },
                    // IStoreProductPagedQueryResult
                    // 6: get_Products
                    (void*)+[](FakeStoreProductPagedQueryResult* This, void** value) -> HRESULT { 
                        LOG("WinRT", INFO, "FakeStoreProductPagedQueryResult::get_Products called!");
                        *value = new FakeMapView(true, This->store_id); // Map of Products
                        return S_OK; 
                    },
                    // 7: get_HasMoreResults
                    (void*)+[](FakeStoreProductPagedQueryResult* This, boolean* value) -> HRESULT { 
                        LOG("WinRT", INFO, "FakeStoreProductPagedQueryResult::get_HasMoreResults called!");
                        *value = false;
                        return S_OK;
                    },
                    // 8: get_ExtendedError
                    (void*)+[](FakeStoreProductPagedQueryResult* This, HRESULT* value) -> HRESULT { 
                        LOG("WinRT", INFO, "FakeStoreProductPagedQueryResult::get_ExtendedError called!");
                        *value = S_OK;
                        return S_OK;
                    },
                    // 9: GetNextAsync
                    (void*)+[](FakeStoreProductPagedQueryResult* This, void** value) -> HRESULT { 
                        LOG("WinRT", INFO, "FakeStoreProductPagedQueryResult::GetNextAsync called!");
                        return E_NOTIMPL; 
                    }
                };
                vtable = vt;
            }
        };

        struct FakeStoreConsumableResult {
            void** vtable;
            long ref_count;
            FakeStoreConsumableResult() : ref_count(1) {
                static void* vt[] = {
                    (void*)+[](FakeStoreConsumableResult* This, const IID& riid, void** ppv) -> HRESULT {
                        *ppv = This; return S_OK;
                    },
                    (void*)+[](FakeStoreConsumableResult* This) -> ULONG { return 2; },
                    (void*)+[](FakeStoreConsumableResult* This) -> ULONG { return 1; },
                    (void*)+[](FakeStoreConsumableResult* This, ULONG* count, IID** iids) -> HRESULT { *count = 0; return S_OK; },
                    (void*)+[](FakeStoreConsumableResult* This, HSTRING* name) -> HRESULT { return E_NOTIMPL; },
                    (void*)+[](FakeStoreConsumableResult* This, int* trust) -> HRESULT { *trust = 0; return S_OK; },
                    // IStoreConsumableResult
                    // 6: get_Status
                    (void*)+[](FakeStoreConsumableResult* This, int* value) -> HRESULT { 
                        *value = 0; // StoreConsumableStatus::Succeeded
                        return S_OK; 
                    },
                    // 7: get_ExtendedError
                    (void*)+[](FakeStoreConsumableResult* This, HRESULT* value) -> HRESULT { 
                        *value = S_OK;
                        return S_OK;
                    },
                    // 8: get_BalanceRemaining
                    (void*)+[](FakeStoreConsumableResult* This, unsigned int* value) -> HRESULT { 
                        *value = 9999; // DUMMY BALANCE
                        return S_OK; 
                    },
                    // 9: get_TrackingId
                    (void*)+[](FakeStoreConsumableResult* This, GUID* value) -> HRESULT { return E_NOTIMPL; }
                };
                vtable = vt;
            }
        };

        struct FakeAsyncOp {
            void** vtable_operation;
            void** vtable_info;
            long ref_count;
            void* result;

            FakeAsyncOp(void* res) : ref_count(1), result(res) {
                static void* vt_op[] = {
                    // IUnknown
                    (void*)+[](FakeAsyncOp* This, const IID& riid, void** ppv) -> HRESULT { return This->QueryInterface(riid, ppv); },
                    (void*)+[](FakeAsyncOp* This) -> ULONG { return 2; },
                    (void*)+[](FakeAsyncOp* This) -> ULONG { return 1; },
                    // IInspectable
                    (void*)+[](FakeAsyncOp* This, ULONG* count, IID** iids) -> HRESULT { *count = 0; return S_OK; },
                    (void*)+[](FakeAsyncOp* This, HSTRING* name) -> HRESULT { return E_NOTIMPL; },
                    (void*)+[](FakeAsyncOp* This, int* trust) -> HRESULT { *trust = 0; return S_OK; },
                    // IAsyncOperation
                    (void*)+[](FakeAsyncOp* This, void* handler) -> HRESULT { 
                        LOG("WinRT", INFO, "FakeAsyncOp::put_Completed called!");
                        if (handler) {
                            void** handler_vtable = *(void***)handler;
                            auto invoke = (HRESULT(__stdcall*)(void*, void*, int))handler_vtable[3];
                            invoke(handler, This, 1); // 1 = Completed
                        }
                        return S_OK; 
                    },
                    (void*)+[](FakeAsyncOp* This, void** handler) -> HRESULT { 
                        LOG("WinRT", INFO, "FakeAsyncOp::get_Completed called!");
                        return S_OK; 
                    },
                    (void*)+[](FakeAsyncOp* This, void** results) -> HRESULT { 
                        LOG("WinRT", INFO, "FakeAsyncOp::GetResults called!");
                        *results = This->result; 
                        return S_OK; 
                    }
                };

                static void* vt_info[] = {
                    (void*)+[](void** ThisVtable, const IID& riid, void** ppv) -> HRESULT { 
                        FakeAsyncOp* This = (FakeAsyncOp*)((char*)ThisVtable - offsetof(FakeAsyncOp, vtable_info));
                        return This->QueryInterface(riid, ppv); 
                    },
                    (void*)+[](void** ThisVtable) -> ULONG { return 2; },
                    (void*)+[](void** ThisVtable) -> ULONG { return 1; },
                    (void*)+[](void** ThisVtable, ULONG* count, IID** iids) -> HRESULT { *count = 0; return S_OK; },
                    (void*)+[](void** ThisVtable, HSTRING* name) -> HRESULT { return E_NOTIMPL; },
                    (void*)+[](void** ThisVtable, int* trust) -> HRESULT { *trust = 0; return S_OK; },
                    // IAsyncInfo
                    (void*)+[](void** ThisVtable, unsigned int* id) -> HRESULT { *id = 1; return S_OK; },
                    (void*)+[](void** ThisVtable, int* status) -> HRESULT { 
                        LOG("WinRT", INFO, "FakeAsyncOp::get_Status called!");
                        *status = 1; 
                        return S_OK; 
                    }, // Completed
                    (void*)+[](void** ThisVtable, HRESULT* errorCode) -> HRESULT { *errorCode = S_OK; return S_OK; },
                    (void*)+[](void** ThisVtable) -> HRESULT { return S_OK; }, // Cancel
                    (void*)+[](void** ThisVtable) -> HRESULT { return S_OK; }  // Close
                };

                vtable_operation = vt_op;
                vtable_info = vt_info;
            }

            HRESULT QueryInterface(const IID& riid, void** ppv) {
                if (!ppv) return E_POINTER;
                
                LOG("WinRT", INFO, "FakeAsyncOp::QueryInterface called for IID: {:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                    riid.Data1, riid.Data2, riid.Data3, riid.Data4[0], riid.Data4[1], riid.Data4[2], riid.Data4[3], riid.Data4[4], riid.Data4[5], riid.Data4[6], riid.Data4[7]);

                // IUnknown
                static const IID IID_IUnknown = { 0x00000000, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
                if (memcmp(&riid, &IID_IUnknown, sizeof(IID)) == 0) {
                    *ppv = &vtable_operation;
                    return S_OK;
                }

                // IInspectable
                static const IID IID_IInspectable = { 0xAF86E2E0, 0xB12D, 0x4C6A, { 0x9C, 0x5A, 0xD7, 0xAA, 0x65, 0x10, 0x1E, 0x90 } };
                if (memcmp(&riid, &IID_IInspectable, sizeof(IID)) == 0) {
                    *ppv = &vtable_operation;
                    return S_OK;
                }

                // IAsyncInfo
                static const IID IID_IAsyncInfo = { 0x00000036, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
                if (memcmp(&riid, &IID_IAsyncInfo, sizeof(IID)) == 0) {
                    *ppv = &vtable_info;
                    return S_OK;
                }

                // IMarshal
                static const IID IID_IMarshal = { 0x00000003, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
                if (memcmp(&riid, &IID_IMarshal, sizeof(IID)) == 0) {
                    LOG("WinRT", INFO, "FakeAsyncOp::QueryInterface rejected IMarshal!");
                    return E_NOINTERFACE;
                }

                // IWeakReferenceSource
                static const IID IID_IWeakReferenceSource = { 0x00000038, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
                if (memcmp(&riid, &IID_IWeakReferenceSource, sizeof(IID)) == 0) {
                    return E_NOINTERFACE;
                }

                // IAgileObject
                static const IID IID_IAgileObject = { 0x94ea2b94, 0xe9cc, 0x49e0, { 0xc0, 0xff, 0xee, 0x64, 0xca, 0x8f, 0x5b, 0x90 } };
                if (memcmp(&riid, &IID_IAgileObject, sizeof(IID)) == 0) {
                    // We can claim to be agile
                    *ppv = &vtable_operation;
                    return S_OK;
                }

                // If it's some other standard COM interface ending in C000000000000046, reject it to be safe
                if (riid.Data4[0] == 0xC0 && riid.Data4[1] == 0x00 && riid.Data4[7] == 0x46) {
                    LOG("WinRT", INFO, "FakeAsyncOp::QueryInterface rejected standard COM interface!");
                    return E_NOINTERFACE;
                }
                
                // Otherwise, assume it's the requested IAsyncOperation<T> parameterised interface
                LOG("WinRT", INFO, "FakeAsyncOp::QueryInterface ACCEPTED unknown interface (assuming IAsyncOperation)!");
                *ppv = &vtable_operation;
                return S_OK;
            }
        };
    }

    template<int Index>
    HRESULT __stdcall vmt_stub_IStoreContextServer(void* a1, void* a2, void* a3, void* a4, void* a5, void* a6, void* a7, void* a8, void* a9, void* a10, void* a11, void* a12) {
        auto orig = get_orig_vmt_func(a1, Index);
        if (!orig) return E_FAIL;
        
        LOG("WinRT", INFO, "IStoreContextServer::Method[{}] called! a2={:p}, a3={:p}, a4={:p}", Index, a2, a3, a4);

        std::wstring requested_store_id;
        if (Index == 14) {
            unsigned int len = 0;
            const wchar_t* raw = WindowsGetStringRawBuffer((HSTRING)a2, &len);
            if (raw && len > 0 && len < 100) {
                requested_store_id = std::wstring(raw, len);
                std::string s(requested_store_id.begin(), requested_store_id.end());
                LOG("WinRT", INFO, "a2 as HSTRING: {}", s);
            } else {
                LOG("WinRT", INFO, "a2 is not a valid HSTRING");
            }
        } else if (Index == 12) {
            requested_store_id = L"9NBLGGH5393R"; // Season Pass ID
            // Log productKinds from a2
            void* ptr = a2;
            if (ptr && !IsBadReadPtr(ptr, sizeof(void*))) {
                void** vtable = *(void***)ptr;
                if (vtable && !IsBadReadPtr(vtable, 10 * sizeof(void*))) {
                    auto First = (HRESULT(__stdcall*)(void*, void**))vtable[6];
                    void* iterator = nullptr;
                    if (SUCCEEDED(First(ptr, &iterator)) && iterator) {
                        void** iter_vtable = *(void***)iterator;
                        if (iter_vtable && !IsBadReadPtr(iter_vtable, 10 * sizeof(void*))) {
                            auto get_Current = (HRESULT(__stdcall*)(void*, HSTRING*))iter_vtable[6];
                            auto get_HasCurrent = (HRESULT(__stdcall*)(void*, boolean*))iter_vtable[7];
                            auto MoveNext = (HRESULT(__stdcall*)(void*, boolean*))iter_vtable[8];

                            boolean hasCurrent = false;
                            while (SUCCEEDED(get_HasCurrent(iterator, &hasCurrent)) && hasCurrent) {
                                HSTRING str = nullptr;
                                if (SUCCEEDED(get_Current(iterator, &str)) && str) {
                                    unsigned int len = 0;
                                    const wchar_t* raw = WindowsGetStringRawBuffer(str, &len);
                                    if (raw) {
                                        std::wstring wstr(raw, len);
                                        std::string s(wstr.begin(), wstr.end());
                                        LOG("WinRT", INFO, "Method 12 productKinds contains: {}", s);
                                    }
                                }
                                MoveNext(iterator, &hasCurrent);
                            }
                        }
                    }
                }
            }
        }

        HRESULT hr = orig(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12);
        LOG("WinRT", INFO, "IStoreContextServer::Method[{}] returned hr: 0x{:08X}", Index, (unsigned int)hr);

        if (Index == 12 || Index == 14) {
            void* out_param = nullptr;
            
            if (Index == 12) {
                out_param = a4;
            } else if (Index == 14) {
                out_param = a3;
            }

            if (out_param && !IsBadWritePtr(out_param, sizeof(void*))) {
                LOG("WinRT", INFO, "Method[{}] failed but out param is at {:p}, creating custom FakeAsyncOp...", Index, out_param);
                if (Index == 12) *(void**)out_param = new Fakes::FakeAsyncOp(new Fakes::FakeStoreProductPagedQueryResult(requested_store_id));
                if (Index == 14) *(void**)out_param = new Fakes::FakeAsyncOp(new Fakes::FakeStoreConsumableResult());
                return S_OK;
            } else {
                LOG("WinRT", ERROR, "Method[{}] failed and out param {:p} is invalid!", Index, out_param);
            }
        }

        return hr;
    }

    HRESULT __stdcall vmt_stub_StoreContextServer_QueryInterface(void* This, REFIID riid, void** ppvObject) {
        auto orig = reinterpret_cast<HRESULT(__stdcall*)(void*, REFIID, void**)>(get_orig_vmt_func(This, 0));
        if (!orig) return E_FAIL;
        HRESULT hr = orig(This, riid, ppvObject);
        if (hr == S_OK && ppvObject && *ppvObject) {
            if (riid.Data1 == 0xa561605d && riid.Data2 == 0x67b1 && riid.Data3 == 0x4f0c) {
                hook_vmt(*ppvObject, "IStoreContextServer", [](auto hook_method) {
                    hook_method(6, reinterpret_cast<void*>(vmt_stub_IStoreContextServer<6>));
                    hook_method(12, reinterpret_cast<void*>(vmt_stub_IStoreContextServer<12>));
                    hook_method(14, reinterpret_cast<void*>(vmt_stub_IStoreContextServer<14>));
                });
            }
        }
        return hr;
    }

    HRESULT __stdcall ro_get_activation_factory_stub(HSTRING activatableClassId, REFIID riid, void** factory) {
        auto orig = reinterpret_cast<RoGetActivationFactory_t>(ro_get_activation_factory_hook.get_original());
        HRESULT hr = orig(activatableClassId, riid, factory);
        return hr;
    }

    HRESULT __stdcall ro_activate_instance_stub(HSTRING activatableClassId, IInspectable** instance) {
        auto orig = reinterpret_cast<RoActivateInstance_t>(ro_activate_instance_hook.get_original());
        HRESULT hr = orig(activatableClassId, instance);
        if (hr == S_OK && instance && *instance) {
            const wchar_t* wstr = WindowsGetStringRawBuffer(activatableClassId, nullptr);
            if (wstr && wcscmp(wstr, L"Windows.Services.Store.Internal.StoreContextServer") == 0) {
                hook_vmt(*instance, "StoreContextServer", [](auto hook_method) {
                    hook_method(0, reinterpret_cast<void*>(vmt_stub_StoreContextServer_QueryInterface));
                });
            }
        }
        return hr;
    }

    void init() {
        HMODULE combase_mod = GetModuleHandleA("combase.dll");
        if (!combase_mod) return;
        void* ro_act_inst = GetProcAddress(combase_mod, "RoActivateInstance");
        if (ro_act_inst) {
            ro_activate_instance_hook.create(ro_act_inst, ro_activate_instance_stub);
            ro_activate_instance_hook.enable();
        }
        void* ro_get_fac = GetProcAddress(combase_mod, "RoGetActivationFactory");
        if (ro_get_fac) {
            ro_get_activation_factory_hook.create(ro_get_fac, ro_get_activation_factory_stub);
            ro_get_activation_factory_hook.enable();
        }
    }
}

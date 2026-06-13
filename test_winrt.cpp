#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Services.Store.h>

using namespace winrt;
using namespace winrt::Windows::Services::Store;

struct MyLicense : implements<MyLicense, IStoreAppLicense> {
    bool IsActive() { return true; }
    bool IsTrial() { return false; }
    bool IsTrialOwnedByThisUser() { return false; }
    hstring SkuStoreId() { return L""; }
    winrt::Windows::Foundation::TimeSpan TrialTimeRemaining() { return {}; }
    hstring TrialUniqueId() { return L""; }
    winrt::Windows::Foundation::DateTime ExpirationDate() { return {}; }
    hstring ExtendedJsonData() { return L"{}"; }
    winrt::Windows::Foundation::Collections::IMapView<hstring, StoreLicense> AddOnLicenses() { return nullptr; }
};

int main() {
    auto lic = make<MyLicense>();
    return 0;
}

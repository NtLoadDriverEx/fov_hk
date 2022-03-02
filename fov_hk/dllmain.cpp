#include <cstdio>
#include <windows.h>
#include "lazyimporter.hpp"
#include "pattern.hpp"
#include "detours/detours.h"

bool add_hook(PVOID* ppPointer, PVOID pDetour, PDETOUR_TRAMPOLINE* ppRealTrampolin = nullptr)
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	if (ppRealTrampolin == nullptr)
		DetourAttach(ppPointer, pDetour);
	else
		DetourAttachEx(ppPointer, pDetour, ppRealTrampolin, NULL, NULL);

	if (DetourTransactionCommit() == NO_ERROR)
	{
		return true;
	}

	return false;
}

/* 14 */
struct fov_struct
{
	BYTE gap0[8];
	float float8;
	BYTE gapC[48];
	float float3C;
	float packed_fov;
};

using update_fov_fn = void*(__fastcall*)(fov_struct* fov);
update_fov_fn update_fov_original;

void* update_fov_hk(fov_struct* fov_struct)
{
	void* result = update_fov_original(fov_struct);
	if (GetAsyncKeyState(VK_OEM_PLUS) & 0x1)
	{
		fov_struct->packed_fov += 5.f / 78.f;
	}

	if (GetAsyncKeyState(VK_OEM_MINUS) & 0x1)
	{
		fov_struct->packed_fov -= 5.f / 78.f;
	}
	return result;
}

void hook_fov()
{
	const auto begin = (unsigned char*)li::detail::peb()->ImageBaseAddress;
	const auto nt_headers = li::detail::nt_headers((const char*)begin);
	const auto end = nt_headers->OptionalHeader.SizeOfImage + begin;

	const auto call_update_fov = FindPattern(begin, end, "E8 ? ? ? ? 41 80 BF ? ? ? ? ? 74 16");
	if(!call_update_fov) MessageBoxA(nullptr, "Out of Date!", "UPDATE REQUIRED", MB_ICONERROR);
	// 1 is the offset from the start of the signature to the rva
	// 5 is the length of the instruction aka a call + 4
	const auto update_fov = *reinterpret_cast<uint32_t*>(call_update_fov + 1) + call_update_fov + 5;
	update_fov_original = reinterpret_cast<decltype(update_fov_original)>(update_fov);
	add_hook(&(PVOID&)update_fov_original, update_fov_hk);
	MessageBoxA(nullptr, "Working use +/- to chagne FOV in game!", "Success!", MB_OK);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
        hook_fov();
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


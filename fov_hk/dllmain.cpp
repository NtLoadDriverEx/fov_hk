#include <cstdio>
#include <windows.h>
#include "lazyimporter.hpp"
#include "pattern.hpp"
#include "hooking.hpp"
#include "sdk.hpp"

update_fov_fn update_fov_original;
#define UWP

#ifdef UWP
constexpr float uwp_fov = 120.f;

void* update_fov_hk(fov_struct* fov_struct)
{
	void* result = update_fov_original(fov_struct);
	fov_struct->packed_fov = uwp_fov / 78.f;
	return result;
}
#else
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
#endif
void hook_fov()
{
	const auto begin = (unsigned char*)li::detail::peb()->ImageBaseAddress;
	const auto nt_headers = li::detail::nt_headers((const char*)begin);
	const auto end = nt_headers->OptionalHeader.SizeOfImage + begin;

	auto call_update_fov = FindPattern(begin, end, "E8 ? ? ? ? 41 80 BF ? ? ? ? ? 74 16");
	while(!call_update_fov) call_update_fov = FindPattern(begin, end, "E8 ? ? ? ? 41 80 BF ? ? ? ? ? 74 16");

	if(!call_update_fov) MessageBoxA(nullptr, "Out of date signature - plz dont spam UC <3!", "UPDATE REQUIRED", MB_ICONERROR);

	const auto update_fov = *reinterpret_cast<uint32_t*>(call_update_fov + 1) + call_update_fov + 5;

	update_fov_original = reinterpret_cast<decltype(update_fov_original)>(update_fov);

	add_hook(&(PVOID&)update_fov_original, update_fov_hk);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    if(ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
    	DisableThreadLibraryCalls(hModule);
        hook_fov();
		MessageBoxA(nullptr, "Working use +/- to chagne FOV in game!", "Success!", MB_OK);

    }
	else if(ul_reason_for_call == DLL_PROCESS_DETACH)
    {
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)update_fov_original, update_fov_hk);
		DetourTransactionCommit();
    }

    return TRUE;
}


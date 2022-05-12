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

void* update_fov_hk(fov_struct* fov_struct, float a2)
{
	void* result = update_fov_original(fov_struct, a2);
	fov_struct->packed_fov = uwp_fov / 78.f;
	return result;
}
#else
void* update_fov_hk(fov_struct* fov_struct)
{
	void* result = update_fov_original(fov_struct);
	if (GetAsyncKeyState(VK_OEM_PLUS) & 0x8000)
	{
		fov_struct->packed_fov += .1f / 78.f;
	}

	if (GetAsyncKeyState(VK_OEM_MINUS) & 0x8000)
	{
		fov_struct->packed_fov -= .1f / 78.f;
	}
	return result;
}
#endif
void hook_fov()
{
	auto update_fov = pattern::scan("40 57 48 83 EC 30 80 79 44 00");
	while(!update_fov) update_fov = pattern::scan("40 57 48 83 EC 30 80 79 44 00");

	if(!update_fov) MessageBoxA(nullptr, "Out of date signature - plz dont spam UC <3!", "UPDATE REQUIRED", MB_ICONERROR);

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
		MessageBoxA(nullptr, "Working use +/- to change FOV in game!", "Success!", MB_OK);

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


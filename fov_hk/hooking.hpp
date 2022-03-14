#pragma once
#include <windows.h>
#include "detours/detours.h"

inline bool add_hook(PVOID* ppPointer, PVOID pDetour, PDETOUR_TRAMPOLINE* ppRealTrampolin = nullptr)
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

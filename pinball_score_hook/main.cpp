#include <Windows.h>
#include <iostream>

#include "detours.h"

#pragma comment(lib, "detours.lib")

DWORD SetScoreAddress = 0x01013C89;
typedef int(__stdcall *SetScore)(int a1, int a2);

int __stdcall HookSetScore(int a1, int a2)
{
	a2 = 999999;
	int result; // eax@1

	result = a1;
	if (a1)
	{
		*(DWORD*)a1 = a2;
		*(DWORD*)(a1 + 4) = 1;
	}
	SetScore originSetScore = (SetScore)SetScoreAddress;

	return originSetScore(a1, a2);

}


BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	// store the address of sum() in testprogram.exe here.

	if (dwReason == DLL_PROCESS_ATTACH)
	{
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		// this will hook the function
		DetourAttach(&(LPVOID&)SetScoreAddress, &HookSetScore);

		DetourTransactionCommit();
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		// unhook
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		// this will hook the function
		DetourDetach(&(LPVOID&)SetScoreAddress, &HookSetScore);

		DetourTransactionCommit();
	}
	return TRUE;
}
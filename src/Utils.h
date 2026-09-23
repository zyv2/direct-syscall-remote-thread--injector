/*****************************************************************************
 * @file        Utils.h
 * @author      Zied Sayari
 *
 * @details
 *  Utility functions and structs
 *****************************************************************************/

#pragma once
#include "PTEB.h"
#include <Windows.h>


/*----------------Sturcts---------------------*/

typedef struct __XX_TABLE_ENTRY
{
	PVOID ptr_function_address;
	DWORD64 hashed_function_name;
	WORD SSN;

} XX_TABLE_ENTRY, * PTR_XX_TABLE_ENTRY;

typedef struct _XX_TABLE
{
	XX_TABLE_ENTRY NtOpenProcess;
	XX_TABLE_ENTRY NtAllocateVirtualMemory;
	XX_TABLE_ENTRY NtWriteVirtualMemory;
	XX_TABLE_ENTRY NtProtectVirtualMemory;
	XX_TABLE_ENTRY NtCreateThreadEx;
	//XX_TABLE_ENTRY NtWaitForSingleObject;
} XX_TABLE, * PTR_XX_TABLE;


/*----------------Utilities---------------------*/

LPVOID get_win_api_func_addr(LPCSTR lib_name, LPCSTR function_name);
BOOL check_hook(LPVOID function_address, const char* function_name);
BOOL isHooked_call_chain_CreateRemoteThreadEx();

//LONG CALLBACK my_handler(PEXCEPTION_POINTERS execption_ptr);
//UINT_PTR find_syscall_address(LPVOID function_address);

PTEB RtlGetPeb();
PIMAGE_EXPORT_DIRECTORY get_image_export_directory(PVOID module_base);
BOOL get_ssn(LPVOID module_base, PIMAGE_EXPORT_DIRECTORY ptr_image_export_directory, PTR_XX_TABLE_ENTRY function_entry);


DWORD64 hash(const char* function_name);


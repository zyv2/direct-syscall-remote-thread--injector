/*****************************************************************************
 * @file        injectors.h
 * @author      Zied Sayari
 *
 * @details
 *  Remote Thread Injection Function Prototypes
 *****************************************************************************/
#pragma once
#include <Windows.h>


// This version perform a normal remote thread injection
BOOL remote_thread_injection_v1(DWORD pid, const BYTE shellcode[], size_t shellcode_length);

// This version check if the CreateRemoteThreadEx call chain is hooked and abort if it is.
BOOL remote_thread_injection_v2(DWORD pid, const BYTE shellcode[], size_t shellcode_length);

// This version calls the ntdll version of each function without checking for hooks.
BOOL remote_thread_injection_v2_1(DWORD pid, const BYTE shellcode[], size_t shellcode_length);

// This version calls the ntdll version of each function and checking for hooks if found the function abort.
BOOL remote_thread_injection_v2_2(DWORD pid, const BYTE shellcode[], size_t shellcode_length);

// This version use direct syscall for each ntdll function (hardcoded SSNs)
BOOL remote_thread_injection_v3(DWORD pid, const BYTE shellcode[], size_t shellcode_length);

// This version use direct syscall for each ntdll function (dynamically resolve SSNs)
BOOL remote_thread_injection_v4(DWORD pid, const BYTE shellcode[], size_t shellcode_length);




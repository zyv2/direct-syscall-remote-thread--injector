;/*****************************************************************************
 ;* @file        direct_syscall_hardcoded.asm
 ;* @author      Zied Sayari
 ;*
 ;* @details
 ;*  Assembly stubs 
 ;*****************************************************************************/

.code
; -------------------------sys_NtOpenProcess--------------------
	sys_NtOpenProcess proc
		mov r10, rcx
		mov eax, 26h ; hardcoded (build dependant)
		syscall
		ret
	sys_NtOpenProcess endp

; --------------------sys_NtAllocateVirtualMemoryEx-------------
	sys_NtAllocateVirtualMemoryEx proc
		mov r10, rcx
		mov eax, 76h ; hardcoded (build dependant)
		syscall
		ret
	sys_NtAllocateVirtualMemoryEx endp

; --------------------sys_NtWriteVirtualMemory------------------
	sys_NtWriteVirtualMemory proc
		mov r10, rcx
		mov eax, 3Ah ; hardcoded (build dependant)
		syscall
		ret
	sys_NtWriteVirtualMemory endp

; --------------------sys_NtProtectVirtualMemory----------------
	sys_NtProtectVirtualMemory proc
		mov r10, rcx
		mov eax, 50h ; hardcoded (build dependant)
		syscall
		ret
	sys_NtProtectVirtualMemory endp

; --------------------sys_NTCreateThreadEx----------------------
	sys_NTCreateThreadEx proc
		mov r10, rcx
		mov eax, 0C2h ; hardcoded (build dependant)
		syscall
		ret
	sys_NTCreateThreadEx endp
end
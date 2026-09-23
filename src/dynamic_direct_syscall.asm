;/*****************************************************************************
 ;* @file        dynamic_direct_syscall.asm
 ;* @author      Zied Sayari
 ;*
 ;* @details
 ;*  Assembly stubs 
 ;*****************************************************************************/


.data
	; Variable to hold our SSN when we pass it
	; So it does not get overwritten.
	syscall_number DWORD 00h

.code
	; Pass target SSN as argument and store into our variable
	set_ssn proc
		mov syscall_number, 00h
		mov syscall_number, ecx
		ret
	set_ssn endp
	
	; Syscall SSN stored syscall_number variable
	invoke_syscall proc
		mov r10, rcx
		mov eax, syscall_number

		syscall
		ret
	invoke_syscall endp
end
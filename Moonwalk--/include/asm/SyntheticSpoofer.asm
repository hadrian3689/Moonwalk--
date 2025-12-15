;	------------------------------------------------------------------------------------
;
;	Author       : klezVirus 2022
;	Twitter      : https://twitter.com/klezVirus
;	Original Idea: Namazso 
;	Twitter      : https://twitter.com/namazso
;	------------------------------------------------------------------------------------
;	------------------------------------------------------------------------------------

spoof_call_synthetic proto
restore_synthetic proto

.data

;  ------------------------------------------------------------------------------------
;   Spoofing Configuration Structure
;   Utility structure to pass all the relevant details from C to ASM regarding the 
;   stack frames to spoof
;  ------------------------------------------------------------------------------------
SPOOFER STRUCT

    KernelBaseAddress               DQ 1
    
    RtlUserThreadStartAddress       DQ 1
    BaseThreadInitThunkAddress      DQ 1

    FirstFrameFunctionPointer       DQ 1
    SecondFrameFunctionPointer      DQ 1
    JmpRbxGadget                    DQ 1
    AddRspXGadget                   DQ 1

    FirstFrameSize                  DQ 1
    FirstFrameRandomOffset          DQ 1
    SecondFrameSize                 DQ 1
    SecondFrameRandomOffset         DQ 1
    JmpRbxGadgetFrameSize           DQ 1
    AddRspXGadgetFrameSize          DQ 1

    RtlUserThreadStartFrameSize     DQ 1
    BaseThreadInitThunkFrameSize    DQ 1

    StackOffsetWhereRbpIsPushed     DQ 1

    JmpRbxGadgetRef                 DQ 1
    SpoofFunctionPointer            DQ 1
    ReturnAddress                   DQ 1

    Nargs                           DQ 1
;   RCX +A0h
    Arg01                           DQ 1
    Arg02                           DQ 1
    Arg03                           DQ 1
    Arg04                           DQ 1
;   RCX +C0h
    Args                            DQ 20

SPOOFER ENDS

.code

spoof_call_synthetic proc
;  ------------------------------------------------------------------------------------
;   Saving non-vol registers
;  ------------------------------------------------------------------------------------
    mov     [rsp+08h], rbp
    mov     [rsp+10h], rbx
    mov     [rsp+18h], r15
;  ------------------------------------------------------------------------------------
;   Creating a stack reference to the JMP RBX gadget
;  ------------------------------------------------------------------------------------
    mov     rbx, [rcx].SPOOFER.JmpRbxGadget
    mov     [rsp+20h], rbx
    mov     rbx, rsp
    add     rbx, 20h
    mov     [rcx].SPOOFER.JmpRbxGadgetRef, rbx
;  ------------------------------------------------------------------------------------
;   Prolog
;   RBP -> Keeps track of original Stack
;   RSP -> Desync Stack for Unwinding Info
;  ------------------------------------------------------------------------------------
;   Note: Everything between RSP and RBP is our new stack frame for unwinding 
;  ------------------------------------------------------------------------------------
    sub     rsp, 200h
    mov     rbp, rsp

;  ------------------------------------------------------------------------------------
;   Creating stack pointer to Restore PROC
;  ------------------------------------------------------------------------------------
    lea     rax, restore_synthetic
    push    rax
        

;   Now RBX contains the stack pointer to Restore PROC  
;  -> Will be called by the JMP [RBX] gadget
    lea     rbx, [rsp]
    
;  ------------------------------------------------------------------------------------
;   Starting Frames Tampering
;  ------------------------------------------------------------------------------------
;   First Frame (Frame preparation)
;   The first frame contains the details 
;  ------------------------------------------------------------------------------------
    push    [rcx].SPOOFER.FirstFrameFunctionPointer                          
    add     qword ptr [rsp], 20h                                      
    
    mov     rax, [rcx].SPOOFER.ReturnAddress
    sub     rax, [rcx].SPOOFER.FirstFrameSize
    sub     rsp, [rcx].SPOOFER.SecondFrameSize
    mov     r10, [rcx].SPOOFER.StackOffsetWhereRbpIsPushed
    mov     [rsp+r10], rax

;  ------------------------------------------------------------------------------------
;   Cutting the call stack. The 0 pushed in this position will be the return address
;   of the next frame "RtlUserThreadStart", making it effectively the originating function
;  ------------------------------------------------------------------------------------
    xor     rax, rax
    push    rax    

;  ------------------------------------------------------------------------------------
;   Here we proceed by adding the two top fake frames:
;       - RtlUserThreadStart
;       - BaseThreadInitThunk
;  ------------------------------------------------------------------------------------    
    mov     rax, [rcx].SPOOFER.FirstFrameFunctionPointer
    sub     rax, [rcx].SPOOFER.FirstFrameSize
    sub     rsp, [rcx].SPOOFER.RtlUserThreadStartFrameSize
    mov     [rsp+30h], rax

;  ------------------------------------------------------------------------------------
;   RtlUserThreadStart
;  ------------------------------------------------------------------------------------
    
    push    [rcx].SPOOFER.RtlUserThreadStartAddress                          
    add     qword ptr [rsp], 21h                                      
    
    sub     rsp, [rcx].SPOOFER.BaseThreadInitThunkFrameSize
    
;  ------------------------------------------------------------------------------------
;   BaseThreadInitThunk
;  ------------------------------------------------------------------------------------

    push    [rcx].SPOOFER.BaseThreadInitThunkAddress                          
    add     qword ptr [rsp], 14h                                   

    mov     rax, [rcx].SPOOFER.RtlUserThreadStartAddress
    sub     rax, [rcx].SPOOFER.RtlUserThreadStartFrameSize
    sub     rsp, [rcx].SPOOFER.JmpRbxGadgetFrameSize
    mov     [rsp+30h], rax
    
;  ------------------------------------------------------------------------------------
;   ROP Frames
;   These two frames contain the ROP gadgets that will be used to restore the original 
;   Control Flow stack
;  ------------------------------------------------------------------------------------
;  ------------------------------------------------------------------------------------
;      1. JMP [RBX] Gadget
;  ------------------------------------------------------------------------------------
    push    [rcx].SPOOFER.JmpRbxGadget
    
    mov     rax, [rcx].SPOOFER.BaseThreadInitThunkAddress
    sub     rax, [rcx].SPOOFER.SecondFrameSize
    sub     rsp, [rcx].SPOOFER.AddRspXGadgetFrameSize
    mov     [rsp+30h], rax
    
    mov     r10, [rcx].SPOOFER.JmpRbxGadget
    mov     [rsp+38h], r10
    
;  ------------------------------------------------------------------------------------
;      2. Stack PIVOT (To restore original Control Flow Stack)
;  ------------------------------------------------------------------------------------
    push    [rcx].SPOOFER.AddRspXGadget


    mov     rax, [rcx].SPOOFER.AddRspXGadgetFrameSize
    mov     [rbp+28h], rax

;  ------------------------------------------------------------------------------------
;   Finalise
;   Placing the pointer to the function to call
;  ------------------------------------------------------------------------------------
    
    mov     rax, [rbp+28h]    
    mov     [rsp+28h], rax    
    mov     rax, [rbp+30h]
    mov     [rsp+30h], rax
    mov     rax, [rcx].SPOOFER.SpoofFunctionPointer
    
    jmp     parameter_handler_synthetic
    jmp     execute_synthetic
spoof_call_synthetic endp
    
restore_synthetic proc
    mov     rsp, rbp
    add     rsp, 200h
    mov     rbp, [rsp+08h]
    mov     rbx, [rsp+10h]
    mov     r15, [rsp+18h]
    ret
restore_synthetic endp

parameter_handler_synthetic proc
	mov		r9, rax
	mov		r8, [rcx].SPOOFER.Nargs	
_internal_handler:
	cmp 	r8, 4
	jle     _handle_four_or_less
	mov		rax, 8
	mul		r8
;	RCX is the SPOOFER config, RCX+0A0h is the first parameter
	mov		r15, qword ptr [rcx+0A0h+rax-8]
	mov     [rsp+rax], r15
	dec     r8
	jmp     _internal_handler
_handle_four_or_less:
    xchg	r9, rax
    mov     r9, [rcx].SPOOFER.Arg04
    mov     r8, [rcx].SPOOFER.Arg03
    mov     rdx, [rcx].SPOOFER.Arg02
    mov     rcx, [rcx].SPOOFER.Arg01
	jmp     execute_synthetic
parameter_handler_synthetic endp

execute_synthetic proc
    jmp     qword ptr rax
execute_synthetic endp


end
#include "Common.h"

#define JMP_PTR_RBX		9215		// 0xff 0x23 --> reversed 0x23 0xff --> to Integer 9215
#define JMP_RBX			0xe3ff		// 0xff 0x23 --> reversed 0x23 0xff --> to Integer 9215
#define JMP_RBP			0x000065ff  // 3 bytes, appended 0 for DWORD , needs shifting on compare
#define JMP_RDI			0x27ff		// 0xff 0x27 --> reversed 0x23 0xff --> to Integer 9215
#define JMP_RSI			0x26ff		// 0xff 0x26 --> reversed 0x23 0xff --> to Integer 9215
#define JMP_R12			0x2424ff41	// 0xff 0x23 --> reversed 0x23 0xff --> to Integer 9215
#define JMP_R13			0x0065ff41	// 0xff 0x23 --> reversed 0x23 0xff --> to Integer 9215
#define JMP_R14			0x0026ff41	// 0xff 0x23 --> reversed 0x23 0xff --> to Integer 9215
#define JMP_R15			0x0027ff41	// 0xff 0x23 --> reversed 0x23 0xff --> to Integer 9215
#define ADD_RSP_0x38	952402760   // 4883C438 --> reversed 38C48348 --> to Integer 952402760
#define ADD_RSP_0x28	0xccccc328c4834840  // \x40\x48\x83\xc4\x28\xc3 --> to Integer 952402760
#define RET				0xc3		// One byte, no conversion needed
#define ADD_RSP_0x80	2160361800  // 4881C480 + 000000C3 --> reversed 80C48148 and C3000000 --> to Integer 2160361800 and 3271557120
#define RET_			0xc300000	// 4 bytes, RET + 3 bytes of ADD_RSP_0x80
#define CALL_NEAR		0xe8	    // 1 bytes,	0xe8						+ 4 bytes offset
#define CALL_NEAR_QPTR	0xff15	    // 2 bytes, 0xff 0x15 -> reversed		+ 4 bytes offset 
#define CALL_FAR_QPTR	0x0015ff48  // 3 bytes, appended 0 for DWORD , needs shifting on compare - 0x48 0xff 0x15 -> reversed  + 4 bytes offset
#define XCHG_RAX_R8  	0xc30000007fb89049  // 8 bytes -> reversed
#define POP_RAX  	0x58  // 8 bytes -> reversed
#define POP_RCX  	0x59  // 8 bytes -> reversed
#define POP_RDX  	0x5a  // 8 bytes -> reversed
#define PUSH_RBX  	0xc353  // 8 bytes -> reversed

#define POP_RDX_OFFSET  	            0x01f9a  // ntdll + offset
#define POP_RCX_R8_R9_R10_R11_OFFSET  	0x8e9d1  // ntdll + offset
#define ADD_RSP_0x28_OFFSET  	        0x2f88e  // ntdll + offset
#define MOV_RSP_R11_OFFSET  	                0xef01b  // ntdll + offset
#define SUPER_ADD_RSP_GADGET_OFFSET  	                0x8635b  // kernelbase + offset


typedef struct
{

	/* POINTERS */
	
	// 0x00
	PVOID CodeBaseAddress;
	PVOID SystemFunction032Address;
	// 0x10
	PVOID VirtualProtectAddress;
	PVOID OldProtection;
	// 0x20
	PVOID PopRdxGadget;
	PVOID PopRegsGadget;
	// 0x30
	PVOID AddRsp28Gadget;
	PVOID MovRspR11Gadget;
	// 0x40
	PVOID  FirstFrameFunctionPointer;
	PVOID  SecondFrameFunctionPointer;
	// 0x50
	PVOID  JmpRbxGadget;
	PVOID  AddRspXGadget;
	// 0x60
	/* SIZES / OFFSETS */
	UINT64 CodeBaseSize;

	UINT64 FirstFrameSize;
	// 0x70
	UINT64 FirstFrameRandomOffset;
	UINT64 SecondFrameSize;
	// 0x80
	UINT64 SecondFrameRandomOffset;

	UINT64 JmpRbxGadgetFrameSize;
	// 0x90
	UINT64 AddRspXGadgetFrameSize;

	PVOID KeyStructPointer;
	// 0xA0
	PVOID DataStructPointer;

	/* FRAME OFFSET */
	UINT64 StackOffsetWhereRbpIsPushed;
	// 0xB0

	/* OTHERS */
	PVOID  JmpRbxGadgetRef;
	PVOID  SpoofFunctionPointer;
	// 0xC0
	PVOID  ReturnAddress;

	/* SPOOFED FOUNCTION NUMBER OF PARAMETERS */
	UINT64 Nargs;
	/* SPOOFED FOUNCTION PARAMETERS */
	PVOID Arg01;
	PVOID Arg02;
	PVOID Arg03;
	PVOID Arg04;
	PVOID Args[20];

	// 0x190
	PVOID  SuperAddRspGadget;
	UINT64 SuperAddRspGadgetSize;
	// 0x1A0
	UINT64 TotalStackSize;
	PVOID RetGadget;
	
	// 0x1B0
	UCHAR Key[40];
	// 1D8
	USTRING KeyStruct;
	// 1F8
	USTRING DataStruct;

	CHAR Title[40];
	CHAR Message[40];
	

} SPOOFER, * PSPOOFER;

VOID PrintConfig(PSPOOFER sConfig) {
	
	printf("[CodeBaseAddress]                - 0x%I64x\n", sConfig->CodeBaseAddress);
	printf("[SystemFunction032Address]       - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0x8));
	printf("[VirtualProtectAddress]          - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0x10));
	printf("[OldProtection]                  - 0x%I64x\n", sConfig->OldProtection);
	printf("[PopRdxGadget]                   - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0x20));
	printf("[PopRegsGadget]                  - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0x28));
	printf("[AddRsp28Gadget]                 - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0x30));
	printf("[MovRspR11Gadget]                - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0x38));
	printf("[FirstFrameFunctionPointer]      - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0x40));
	printf("[SecondFrameFunctionPointer]     - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0x48));
	printf("[JmpRbxGadget]                   - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0x50));
	printf("[AddRspXGadget]                  - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0x58));
	printf("[CodeBaseSize]                   - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0x60));
	printf("[FirstFrameSize]                 - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0x68));
	printf("[FirstFrameRandomOffset]         - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0x70));
	printf("[SecondFrameSize]                - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0x78));
	printf("[SecondFrameRandomOffset]        - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0x80));
	printf("[JmpRbxGadgetFrameSize]          - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0x88));
	printf("[AddRspXGadgetFrameSize]         - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0x90));
	printf("[KeyStructPointer]               - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0x98));
	printf("[DataStructPointer]              - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0xa0));
	printf("[StackOffsetWhereRbpIsPushed]    - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0xa8));
	printf("[JmpRbxGadgetRef]                - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0xb0));
	printf("[SpoofFunctionPointer]           - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0xb8));
	printf("[ReturnAddress]                  - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0xc0));

	printf("[Nargs]                          - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0xc8));
	printf("[Arg01]                          - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0xd0));
	printf("[Arg02]                          - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0xd8));
	printf("[Arg03]                          - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0xe0));
	printf("[Arg04]                          - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0xe8));
	
	for (int i = 0; i < 20; i++){
		printf("[Arg%02d]                          - 0x%I64x\n", i, *(UINT64*)((CHAR*)sConfig + 0xf0 + (i * 8)));
	}
	
	printf("[SuperAddRspGadget]              - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0x190));
	printf("[SuperAddRspGadgetSize]          - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0x198));
	printf("[TotalStackSize]                 - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0x1A0));
	printf("[RetGadget]                      - 0x%I64x\n", *(UINT64*)((CHAR*)sConfig + 0x1A8));
	printf("[Key[40]]                        - %s\n", (UINT64)sConfig + 0x1B0);

	printf("[KeyStruct]                      - 0x%04x, 0x%04x, 0x%I64x\n", sConfig->KeyStruct.Length, sConfig->KeyStruct.MaximumLength, sConfig->KeyStruct.Buffer);
	printf("[DataStruct]                     - 0x%04x, 0x%04x, 0x%I64x\n", sConfig->DataStruct.Length, sConfig->DataStruct.MaximumLength, sConfig->DataStruct.Buffer);

	printf("[Title[40]]                      - %s\n", (UINT64)sConfig + 0x1F8);
	printf("[Message[40]]                    - %s\n", (UINT64)sConfig + 0x220);

}


VOID SpoofCallStack(PSPOOFER);
EXTERN_C PVOID spoof_call(PSPOOFER sConfig);
EXTERN_C PVOID get_current_rsp();

void research_main();
void main_main();

DWORD _Hton(DWORD value)
{
	PUCHAR s = (PUCHAR)&value;
	return (DWORD)(s[0] << 24 | s[1] << 16 | s[2] << 8 | s[3]);

}
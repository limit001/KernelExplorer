/*++

Copyright (c) 1990-98  Microsoft Corporation All Rights Reserved

Module Name:

    sioctl.c

Abstract:

    Purpose of this driver is to demonstrate how the four different types
    of IOCTLs can be used, and how the I/O manager handles the user I/O
    buffers in each case. This sample also helps to understand the usage of
    some of the memory manager functions.

Environment:

    Kernel mode only.

--*/


//
// Include files.
//

#include <ntddk.h>          // various NT definitions
#include <string.h>

#include "sioctl.h"

#define NT_DEVICE_NAME      L"\\Device\\SIOCTL"
#define DOS_DEVICE_NAME     L"\\DosDevices\\IoctlTest"

#if DBG
#define SIOCTL_KDPRINT(_x_) \
                DbgPrint("SIOCTL.SYS: ");\
                DbgPrint _x_;

#else
#define SIOCTL_KDPRINT(_x_)
#endif

typedef unsigned __int8     BYTE, * PBYTE;
typedef unsigned __int16    WORD, * PWORD;
typedef unsigned __int32    DWORD, * PDWORD;
typedef unsigned __int64    QWORD, * PQWORD;

typedef unsigned char   BYTE2;
typedef unsigned short  WORD2;
typedef unsigned int    DWORD2;


//
// Device driver routine declarations.
//
void Int3();
void __sgdt(_Out_ void* gdtr);
void farjmp2();
void nasm_farjmp2es();
void DisableWP();
__int64 Read60h();
__int64 Write60h();
__int64 ReadCr0();
__int64 ReadCr3();
__int64 ReadCr4();
void Old80();
void Write43h(QWORD	qwData);
void Write40h(QWORD	qwData);

#pragma alloc_text( NONPAGED, Old80)

#pragma pack(1)
#pragma warning(disable:4214) 
typedef struct _SEG_DEC
{
    WORD wLimit1;
    WORD wBase1;
    BYTE byBase2;
    BYTE bType : 4;
    BYTE bS : 1;
    BYTE bDpl : 2;
    BYTE bP : 1;
    BYTE bLimit2 : 4;
    BYTE bAvl : 1;
    BYTE bDB : 1;
    BYTE bG : 1;
    BYTE byBase3;
}SEG_DEC, * PSEG_DES;
typedef struct _SEGMENT
{
    WORD 	wLimit1;
    WORD 	wBase1;

    BYTE	byBase2;

    BYTE	bType : 4;
    BYTE	bS : 1;
    BYTE	bDpl : 2;
    BYTE	bP : 1;

    BYTE	bLimit2 : 4;
    BYTE	bAvl : 1;
    BYTE	bL : 1;
    BYTE	bDb : 1;
    BYTE	bG : 1;
    BYTE	byBase3;
}SEGMENT, * PSEGMENT;


typedef struct _SEGMENT_DESCRIPTOR
{
    // 15:0
    WORD                SegmentLimitLow;            // Segment Limit 15:0
    // 31:16
    WORD                BaseAddressLow;             // Base Address 15:0
    // 39:32
    BYTE                BaseAddressMid;             // Base Address 23:16
    // 43:40
    BYTE                Type : 4;
    // 44
    BYTE                DescriptorType : 1;     // (0 = System; 1 = code or data)
    // 46:45
    BYTE                DPL : 2;
    // 47
    BYTE                Present : 1;
    
    // 51:48
    BYTE                SegmentLimitHigh : 4;     // Segment Limit 19:16
    // 52
    BYTE                AVL : 1;     // Available for use by system SW
    // 53
    BYTE                L : 1;     // 1 = 64-bit code segment
    // 54
    BYTE                D_B : 1;     // Default Operation Size
    // 55
    BYTE                G : 1;     // granularity
    // 63:56
    BYTE                BaseAddressHigh;            // Base Address 31:24
} SEGMENT_DESCRIPTOR, * PSEGMENT_DESCRIPTOR;

typedef struct _GDT
{
    // IDTR(Limit) <-- SRC[0:15];
    WORD                    Limit;
    // IDTR(Base)  <-- SRC[16:79];
    SEGMENT_DESCRIPTOR* Base;
} GDT, * PGDT;

typedef struct _TSS_32 {
    WORD prev_task_link, res0;
    DWORD esp0;
    WORD ss0, res8;
    DWORD esp1;
    WORD ss1, res16;
    DWORD esp2;
    WORD ss2, res24;
    DWORD cr3;
    DWORD eip;
    DWORD eflags;
    DWORD eax;
    DWORD ecx;
    DWORD edx;
    DWORD ebx;
    DWORD esp;
    DWORD ebp;
    DWORD esi;
    DWORD edi;
    WORD es, res72;
    WORD cs, res76;
    WORD ss, res80;
    WORD ds, res84;
    WORD fs, res88;
    WORD gs, res92;
    WORD ldt_set_selector, res96;
    WORD t_flag, io_map_base_address;
} TSS_32, * PTSS_32;

typedef struct CallGateDescriptor
{
    WORD wOffset1;
    WORD wSelector;
    BYTE byReserved1;
    BYTE bType1 : 4;
    BYTE bitReserved2 : 1;
    BYTE bDpl : 2;
    BYTE bP : 1;
    WORD wOffset2;
    DWORD dwOffset3;
    BYTE byReserved3;
    BYTE bType2 : 5;
    BYTE bReserved4 : 3;
    DWORD dwReserved5;
}CALLGATEDES, * PCALLGATEDES;
typedef struct TssDescriptor
{
    WORD wLimit1;
    WORD wBase1;
    BYTE byBase2;
    BYTE bType : 4;//8-11
    BYTE bReserved1 : 1;
    BYTE bDpl : 2;
    BYTE bP : 1;
    BYTE bLimit2 : 4; //19-16
    BYTE bAvl : 1;
    BYTE bReserved2 : 1;
    BYTE bReserved3 : 1;
    BYTE bG : 1;
    BYTE byBase3;
    DWORD dwBase4;
    BYTE byReserved4;
    BYTE bReserved4 : 5;
    BYTE bReserved5 : 3;
    WORD dwReserved6;
}TSSDES, * PTSSDES;

typedef struct _IDT_DESCRIPTOR
{
    WORD wOffset1;
    WORD wSelector;

    BYTE bIst : 3; //0-2
    BYTE bReserved1 : 1; //3
    BYTE bReserved2 : 1; //
    BYTE bReserved3 : 3;

    BYTE bType : 4;//8 9 10 11
    BYTE bReserved4 : 1;
    BYTE bDpl : 2;
    BYTE bP : 1;

    WORD wOffset2;
    DWORD dwOffset3;
    DWORD dwReserved;
} IDT_DESCRIPTOR, * PIDT_DESCRIPTOR;

typedef struct _IDT
{
    // IDTR(Limit) <-- SRC[0:15];
    WORD                    Limit;
    // IDTR(Base)  <-- SRC[16:79];
    PIDT_DESCRIPTOR Base;
} IDT, * PIDT;

typedef struct _TSS_64 {
    DWORD   dwReserved1;
    DWORD   dwRSP0_1;
    DWORD   dwRSP0_2;
    DWORD   dwRSP1_1;
    DWORD   dwRSP1_2;
    DWORD   dwRSP2_1;
    DWORD   dwRSP2_2;
    DWORD   dwReserved2;
    DWORD   dwReserved3;
    DWORD   dwIST1_1;
    DWORD   dwIST1_2;
    DWORD   dwIST2_1;
    DWORD   dwIST2_2;
    DWORD   dwIST3_1;
    DWORD   dwIST3_2;
    DWORD   dwIST4_1;
    DWORD   dwIST4_2;
    DWORD   dwIST5_1;
    DWORD   dwIST5_2;
    DWORD   dwIST6_1;
    DWORD   dwIST6_2;
    DWORD   dwIST7_1;
    DWORD   dwIST7_2;
    DWORD   dwReserved4;
    DWORD   dwReserved5;
    WORD    wReserved6;
    WORD    wIoMapBase;
}TSS_64, *PTSS_64;

typedef union _CR3
{
    QWORD	cr3;
    struct {
        QWORD	Ign : 3;
        QWORD	PWT : 1;
        QWORD	PCD : 1;
        QWORD	Ignored : 7;
        QWORD	PML4 : 40;
        QWORD	ReservedMBZ : 12;
    };

}CR3, * PCR3;
#pragma pack()

GDT     g_gdt = { 0, };
IDT     g_idt = { 0, };

BYTE g_byOldType = 0;
KTIMER	g_myTimer;
KDPC	g_myDpc;
LARGE_INTEGER  g_due = { 0 };
char*   g_pOld80 = 0;
#define DELAY_ONE_MICROSEC (-10)
#define DELAY_ONE_MILLISEC (DELAY_ONE_MICROSEC * 1000)
// Win10 1511 10586
//#define PID_OFFSET 0x2e8
//#define PS_ACTIVE_OFFSET 0x2f0
//#define VAD_ROOT_OFFSET 0x610
//#define DTB_OFFSET 0x028
//#define WORKINGSETSIZE_OFFSET 0x578

// Win7 7601 24000
//#define PID_OFFSET 0x180
//#define PS_ACTIVE_OFFSET 0x188
//#define VAD_ROOT_OFFSET 0x448
//#define DTB_OFFSET 0x028
//#define WORKINGSETSIZE_OFFSET 0x3e0


// Win10 1909 18363
//#define PID_OFFSET 0x2e8
//#define PS_ACTIVE_OFFSET 0x2f0
//#define VAD_ROOT_OFFSET 0x658
//#define DTB_OFFSET 0x028
//#define WORKINGSETSIZE_OFFSET 0x588

// Win10 Pro 16299
//#define PID_OFFSET 0x2e0
//#define PS_ACTIVE_OFFSET 0x2e8
//#define VAD_ROOT_OFFSET 0x628
//#define DTB_OFFSET 0x028
//#define WORKINGSETSIZE_OFFSET 0x588

// Win 10 Home 18362
//#define PID_OFFSET 0x2e8
//#define PS_ACTIVE_OFFSET 0x2f0
//#define VAD_ROOT_OFFSET 0x658
//#define DTB_OFFSET 0x028

// Windows 10 19041 x64
#define PID_OFFSET 0x440
#define PS_ACTIVE_OFFSET 0x448
#define DTB_OFFSET 0x028

#define TRUE 1
#define FALSE 0

typedef unsigned int BOOL;
#define RELATIVE(wait) 			(-(wait))
#define NANOSECONDS(nanos) \
								(((signed __int64)(nanos)) / 100L)
#define MICROSECONDS(micros) \
								(((signed __int64)(micros)) * NANOSECONDS(1000L))
#define MILLISECONDS(milli) \
								(((signed __int64)(milli)) * MICROSECONDS(1000L))
#define SECONDS(seconds) \
								(((signed __int64)(seconds)) * MILLISECONDS(1000L))

int g_nCnt = 0;
void SetClock(WORD byTimeoutPerSec)
{
    LARGE_INTEGER Interval;
    Interval.QuadPart = RELATIVE(SECONDS(1));

    WORD wTime = (WORD)1193180 / (WORD)byTimeoutPerSec;

    if ( g_nCnt == 0 )
        Write43h(0x34);
 //   KeDelayExecutionThread(0, 0, &Interval);

    if (g_nCnt == 1)
        Write40h(wTime & 0xff);
 //   KeDelayExecutionThread(0, 0, &Interval);
    if (g_nCnt == 2)
        Write40h(wTime >> 8);
//    KeDelayExecutionThread(0, 0, &Interval);

}
BOOL IsValidAddr(void* ptr)
{
    BOOL bRet = TRUE;

    if (ptr == NULL)
    {
        bRet = FALSE;
    }

    if (!MmIsAddressValid(ptr))
    {
        bRet = FALSE;
    }
    return bRet;
}

BYTE* FindPatten(const BYTE* start,
    size_t length,
    BYTE* pattern,
    size_t pattern_length)
{
    BYTE* data = (BYTE*)start;

    for (int i = 0; i < length; i++)
    {
        BOOL found = TRUE;

        for (int j = 0; j < pattern_length; j++)
        {
            if (length <= (i + j))
            {
                found = FALSE;
                break;
            }
            
            if (!IsValidAddr(start + i + j))
            {
                found = FALSE;
                break;
            }
            if (data[i + j] != pattern[j])
            {
                found = FALSE;
                break;
            }
        }

        if (found)
        {
            return start + i;
        }
    }

    return NULL;
}
DWORD64 FindProcessEPROC(
    _In_ int terminatePID
)
{
    DWORD64 eproc = 0x00000000;
    int currentPID = 0;
    int startPID = 0;
    int iCount = 0;
    PLIST_ENTRY plistActiveProcs;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nFindProcessEPROC: Entry\n\n"));

    if (terminatePID == 0) {
        return terminatePID;
    }
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nSearch EPROCESS by Id: %d\n\n", terminatePID));
    // Get the address of the current EPROCESS
    eproc = (DWORD64)PsGetCurrentProcess();
    startPID = *((DWORD64*)(eproc + PID_OFFSET));
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nCurrent Process Id: %d\n\n", startPID));
    currentPID = startPID;
    // compare PIDs and walk through the list
    for (;;)
    {
        if (terminatePID == currentPID)
        {
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nfound\n\n"));
            return eproc;// found
        }
        else if ((iCount >= 1) && (startPID == currentPID))
        {
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "not found"));
            return 0x00000000;
        }
        else {
            // Advance in the list.
            plistActiveProcs = (LIST_ENTRY*)(eproc + PS_ACTIVE_OFFSET);
            eproc = (DWORD64)plistActiveProcs->Flink;
            eproc = eproc - PS_ACTIVE_OFFSET;
            currentPID = *((DWORD64*)(eproc + PID_OFFSET));
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Current PID: %016llx\n", currentPID));
            iCount++;
        }
    }

    return 0;
}
DWORD64 GetProcessDirBase(
    _In_ DWORD64 eproc
) {
    DWORD64	directoryTableBase;

    if (eproc == 0x0) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nEPROC should not be 0x0\n\n"));
        return 0x0;
    }

    //get DTB out of PCB
    directoryTableBase = *(DWORD64*)(eproc + DTB_OFFSET);
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nDTB: 0x%llx\n\n", directoryTableBase));

    return directoryTableBase;
}

VOID MyDpcFunc(PKDPC Dpc, PVOID context, PVOID SysArgument1, PVOID SysArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(SysArgument1);
    UNREFERENCED_PARAMETER(SysArgument2);

     DbgPrintEx(DPFLTR_IHVDRIVER_ID,
           0,
          " g_gdt.Base[8].Type = %x\r\n", g_byOldType);

 //    g_gdt.Base[8].Type = g_byOldType;

//    __int64 rax = 0;
//   rax = Read60h();
//   DbgPrintEx(DPFLTR_IHVDRIVER_ID,
//       0,
//      "Read60h : %X\r\n", rax);
    if (g_nCnt == 3)
         g_nCnt = 0;
 
    SetClock(1000);
    g_nCnt++;
   
    KeSetTimer(&g_myTimer, g_due, &g_myDpc);
}

DRIVER_INITIALIZE DriverEntry;

_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH SioctlCreateClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH SioctlDeviceControl;

DRIVER_UNLOAD SioctlUnloadDriver;

VOID
PrintIrpInfo(
    PIRP Irp
    );
VOID
PrintChars(
    _In_reads_(CountChars) PCHAR BufferAddress,
    _In_ size_t CountChars
    );

#ifdef ALLOC_PRAGMA
#pragma alloc_text( INIT, DriverEntry )
#pragma alloc_text( PAGE, SioctlCreateClose)
#pragma alloc_text( PAGE, SioctlDeviceControl)
#pragma alloc_text( PAGE, SioctlUnloadDriver)
#pragma alloc_text( PAGE, PrintIrpInfo)
#pragma alloc_text( PAGE, PrintChars)
#endif // ALLOC_PRAGMA

#define PHYADDRW 48
#define GET_BITS(x, start, end) (((x) & (~0ULL >> (64 - (end)))) >> (start))
enum paging_mode {
    pm_none = 0,
    pm_32_bit = 1,
    pm_pae = 2,
    pm_ia_32e = 3
};
//#define PAGE_SIZE   4096
/* Construct virtual addresses which point to the PTE of a given virtual address */
#define VA_PML4E(va) (QWORD *)((-1ULL << PHYADDRW) | (GET_BITS(va, 39, 48) << 3) | (pml4_self_index << (PHYADDRW - 9)) | (pml4_self_index << (PHYADDRW - 18)) | (pml4_self_index << (PHYADDRW - 27)) | (pml4_self_index << (PHYADDRW - 36)))
#define VA_PDPTE(va) (QWORD *)((-1ULL << PHYADDRW) | (GET_BITS(va, 30, 48) << 3) | (pml4_self_index << (PHYADDRW - 9)) | (pml4_self_index << (PHYADDRW - 18)) | (pml4_self_index << (PHYADDRW - 27)))
#define VA_PDE(va)   (QWORD *)((-1ULL << PHYADDRW) | (GET_BITS(va, 21, 48) << 3) | (pml4_self_index << (PHYADDRW - 9)) | (pml4_self_index << (PHYADDRW - 18)))
#define VA_PTE(va)   (QWORD *)((-1ULL << PHYADDRW) | (GET_BITS(va, 12, 48) << 3) | (pml4_self_index << (PHYADDRW - 9)))

/* Page flags in the different levels */
#define PFLAG_P   (1UL<<0) /* page is present */
#define PFLAG_RW  (1UL<<1) /* page has write permission */
#define PFLAG_US  (1UL<<2) /* user has permission */
#define PFLAG_PWT (1UL<<3) /* page is write-through, false means write-back */
#define PFLAG_PCD (1UL<<4) /* page will not be cached */
#define PFLAG_A   (1UL<<5) /* CPU has read or written to this PE */
#define PFLAG_D   (1UL<<6) /* CPU has written to this page */
#define PFLAG_PS  (1UL<<7) /* page size */
#define PFLAG_PAT (1UL<<7) /* type of memory to access this page (4KB (PTE's) pages only) */
#define PFLAG_G   (1UL<<8) /* translation is global */
#define PFLAG_NXE (1UL<<63)/* page is not executable */

#define PML4_CACHE_DISABLED(ptr) ((ptr) & PFLAG_PCD ) /* True if the PML4 will not be cached */

/**
 * Read a 64-bit value from a MSR. The A constraint stands for concatenation
 * of registers EAX and EDX.
 */
/*
static inline uint64_t rdmsr(uint32_t msr_id) {
    uint32_t msr_lo, msr_hi;
    __asm__ __volatile__("rdmsr" : "=a" (msr_lo), "=d" (msr_hi) : "c" (msr_id));
    return (uint64_t)msr_hi << 32 | (uint64_t)msr_lo;
}
*/
/**
* Determines the current paging mode of the CPU
* For info on CR* register formats see section 2.5
* For info on sequence of checks see section 4.1.1
*/
int get_paging_mode(void) {
    QWORD cr0, cr4, ia32_efer;
    cr0 = ReadCr0();
    /* Check PG (bit 31) of CR0 to see if paging is enabled */
    if (!((cr0 >> 31) & 1)) {
        return pm_none;
    }
    cr4 = ReadCr4();
    /*:) Check PAE (bit 5) of CR4 to see if PAE is enabled */
    if (!((cr4 >> 5) & 1)) {
        return pm_32_bit;
    }
    //ia32_efer = rdmsr(MSR_EFER);
    /* Check LME (IA-32e Mode Enabled) (bit 8) of IA32_EFER (MSR C0000080H) */
    /*:)
    if (!((ia32_efer >> 8) & 1)) {
        return pm_pae;
    }*/
    return pm_ia_32e;
}

#pragma pack(1)

typedef struct _PML4E
{
    union
    {
        struct
        {
            QWORD Present : 1;              // Must be 1, region invalid if 0.
            QWORD ReadWrite : 1;            // If 0, writes not allowed.
            QWORD UserSupervisor : 1;       // If 0, user-mode accesses not allowed.
            QWORD PageWriteThrough : 1;     // Determines the memory type used to access PDPT.
            QWORD PageCacheDisable : 1;     // Determines the memory type used to access PDPT.
            QWORD Accessed : 1;             // If 0, this entry has not been used for translation.
            QWORD Ignored1 : 1;
            QWORD PageSize : 1;             // Must be 0 for PML4E.
            QWORD Ignored2 : 4;
            QWORD PageFrameNumber : 36;     // The page frame number of the PDPT of this PML4E.
            QWORD Reserved : 4;
            QWORD Ignored3 : 11;
            QWORD ExecuteDisable : 1;       // If 1, instruction fetches not allowed.
        };
        QWORD Value;
    };
} PML4E, * PPML4E;
//https://gist.github.com/mvankuipers/94e4f794c6909bd124d7eaf6e840a232
typedef struct _PDPTE
{
    union
    {
        struct
        {
            QWORD Present : 1;              // Must be 1, region invalid if 0.
            QWORD ReadWrite : 1;            // If 0, writes not allowed.
            QWORD UserSupervisor : 1;       // If 0, user-mode accesses not allowed.
            QWORD PageWriteThrough : 1;     // Determines the memory type used to access PD.
            QWORD PageCacheDisable : 1;     // Determines the memory type used to access PD.
            QWORD Accessed : 1;             // If 0, this entry has not been used for translation.
            QWORD Ignored1 : 1;
            QWORD PageSize : 1;             // If 1, this entry maps a 1GB page.
            QWORD Ignored2 : 4;
            QWORD PageFrameNumber : 36;     // The page frame number of the PD of this PDPTE.
            QWORD Reserved : 4;
            QWORD Ignored3 : 11;
            QWORD ExecuteDisable : 1;       // If 1, instruction fetches not allowed.
        };
        QWORD Value;
    };
} PDPTE, * PPDPTE;
typedef struct _PDE
{
    union
    {
        struct
        {
            QWORD Present : 1;              // Must be 1, region invalid if 0.
            QWORD ReadWrite : 1;            // If 0, writes not allowed.
            QWORD UserSupervisor : 1;       // If 0, user-mode accesses not allowed.
            QWORD PageWriteThrough : 1;     // Determines the memory type used to access PT.
            QWORD PageCacheDisable : 1;     // Determines the memory type used to access PT.
            QWORD Accessed : 1;             // If 0, this entry has not been used for translation.
            QWORD Ignored1 : 1;
            QWORD PageSize : 1;             // If 1, this entry maps a 2MB page.
            QWORD Ignored2 : 4;
            QWORD PageFrameNumber : 36;     // The page frame number of the PT of this PDE.
            QWORD Reserved : 4;
            QWORD Ignored3 : 11;
            QWORD ExecuteDisable : 1;       // If 1, instruction fetches not allowed.
        };
        QWORD Value;
    };
} PDE, * PPDE;

typedef struct _PTE
{
    union
    {
        struct
        {
            ULONG64 Present : 1;              // Must be 1, region invalid if 0.
            ULONG64 ReadWrite : 1;            // If 0, writes not allowed.
            ULONG64 UserSupervisor : 1;       // If 0, user-mode accesses not allowed.
            ULONG64 PageWriteThrough : 1;     // Determines the memory type used to access the memory.
            ULONG64 PageCacheDisable : 1;     // Determines the memory type used to access the memory.
            ULONG64 Accessed : 1;             // If 0, this entry has not been used for translation.
            ULONG64 Dirty : 1;                // If 0, the memory backing this page has not been written to.
            ULONG64 PageAccessType : 1;       // Determines the memory type used to access the memory.
            ULONG64 Global : 1;                // If 1 and the PGE bit of CR4 is set, translations are global.
            ULONG64 Ignored2 : 3;
            ULONG64 PageFrameNumber : 36;     // The page frame number of the backing physical page.
            ULONG64 Reserved : 4;
            ULONG64 Ignored3 : 7;
            ULONG64 ProtectionKey : 4;         // If the PKE bit of CR4 is set, determines the protection key.
            ULONG64 ExecuteDisable : 1;       // If 1, instruction fetches not allowed.
        };
        ULONG64 Value;
    };
} PTE, * PPTE;
#pragma pack()
//https://gist.github.com/mvankuipers/c88cdc2a2b3b5ca9d97820b85b33f11c

#define PE_PHYS_ADDR(pe) ((QWORD *)((pe) & 0x0000FFFFFFFFF000UL))

/**
* NOTE: This code assumes the current page tables are 1-1 virtual-to-physical
*
* Traverse each entry in the Page Map level-4 Table pointed to by the physical
* address in cr3
*
* @pml4: The physical address of the PML4 page table
*/
#define PAGE_ENTRIES 512
#define PML4E_PRESENT(ptr)        ((ptr) & PFLAG_P   ) /* True if the PML4E is present */
#define PML4E_WRITE(ptr)          ((ptr) & PFLAG_RW  ) /* True if the PML4E has write permission */
#define PML4E_USER(ptr)           ((ptr) & PFLAG_US  ) /* True if the user has permission */
#define PML4E_WRITE_THROUGH(ptr)  ((ptr) & PFLAG_PWT ) /* True if the PML4E is write-through, false means write-back */
#define PML4E_CACHE_DISABLED(ptr) ((ptr) & PFLAG_PCD ) /* True if the PML4E will not be cached */
#define PML4E_ACCESSED(ptr)       ((ptr) & PFLAG_A   ) /* True if the CPU has read or written to this PML4E */
/* Page Directory Pointer Table Entry macros */
#define PDPTE_PRESENT(ptr)        ((ptr) & PFLAG_P   ) /* True if the PDPTE is present */
#define PDPTE_WRITE(ptr)          ((ptr) & PFLAG_RW  ) /* True if the PDPTE has write permission */
#define PDPTE_USER(ptr)           ((ptr) & PFLAG_US  ) /* True if the user has permission */
#define PDPTE_WRITE_THROUGH(ptr)  ((ptr) & PFLAG_PWT ) /* True if the PDPTE is write-through, false means write-back */
#define PDPTE_CACHE_DISABLED(ptr) ((ptr) & PFLAG_PCD ) /* True if the PDPTE will not be cached */
#define PDPTE_ACCESSED(ptr)       ((ptr) & PFLAG_A   ) /* True if the CPU has read or written to this PDPTE */
#define PDPTE_DIRTY(ptr)          ((ptr) & PFLAG_D   ) /* True if the CPU has written to this 1GB page, NOTE: PS must be 1 */
#define PDPTE_1GB_PAGE(ptr)       ((ptr) & PFLAG_PS  ) /* True if page size is 1GB, false if it's a PD address */
#define PDPTE_GLOBAL(ptr)         ((ptr) & PFLAG_G   ) /* True if the translation is global */
/* Page Directory Entry macros */
#define PDE_PRESENT(ptr)        ((ptr) & PFLAG_P   ) /* True if the PDE is present */
#define PDE_WRITE(ptr)          ((ptr) & PFLAG_RW  ) /* True if the PDE has write permission */
#define PDE_USER(ptr)           ((ptr) & PFLAG_US  ) /* True if the user has permission */
#define PDE_WRITE_THROUGH(ptr)  ((ptr) & PFLAG_PWT ) /* True if the PDE is write-through, false means write-back */
#define PDE_CACHE_DISABLED(ptr) ((ptr) & PFLAG_PCD ) /* True if the page will not be cached */
#define PDE_ACCESSED(ptr)       ((ptr) & PFLAG_A   ) /* True if the CPU has read or written to this PDE */
#define PDE_DIRTY(ptr)          ((ptr) & PFLAG_D   ) /* True if the CPU has written to this 2-MB page, NOTE: PS must be 1 */
#define PDE_2MB_PAGE(ptr)       ((ptr) & PFLAG_PS  ) /* True if page size is 2MB, false if it's a PT address */
#define PDE_GLOBAL(ptr)         ((ptr) & PFLAG_G   ) /* True if the translation is global */
PPML4E g_pml4 = NULL;
PPDPTE g_pdpt = NULL;
PPDE g_pd = NULL;
PPTE g_pt = NULL;

void WalkPt(int nPml4Index, int nPdptIndex, int nPdIndex, QWORD* pyPt)
{
    int i;
    PHYSICAL_ADDRESS phys = { 0 };
    phys.QuadPart = pyPt;

    g_pt = (PPTE)MmGetVirtualForPhysical(phys);
    if (!IsValidAddr(g_pt))
        return;

    for(i = 0; i < PAGE_ENTRIES; i++) 
    {
        PTE pte = g_pt[i];

        /* Print flags of this pml4 entry */

        if(PDE_PRESENT(pte.Value)) 
        {
            /* Print info */
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
                "PML4[%03d].PDPT[%03d].PDP[%03d].PT[%03d].PageFrameNumber : %LX\n",
                nPml4Index, nPdptIndex, nPdIndex, i, pte.PageFrameNumber);
            PHYSICAL_ADDRESS phys2 = { 0 };
            phys2.QuadPart = pyPt;
//            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Pt.PageFrameNumber:%X\n", pte.PageFrameNumber);
            BYTE* pPage = (BYTE*)MmGetVirtualForPhysical(phys2);
            if (nPml4Index == 3 && nPdptIndex == 1 && nPdIndex == 441 && i == 42)
            {
                Int3();
            }
            if (!IsValidAddr(pPage))
                return;
            if (NULL != FindPatten(pPage, 4096, L"MICHINGAMZA", 22))
            {
                Int3();
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
                    "MICHINGAMZA find!!!\n");
            }
        }
        else
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
                "PML4[%03d].PDPT[%03d].PDP[%03d].PT[%03d].PageFrameNumber : %LX is not present\n",
                nPml4Index, nPdptIndex, nPdIndex, i, pte.PageFrameNumber);

        }
    }
}


void WalkPd(int nPml4Index, int nPdptIndex, QWORD* pyPd) 
{
    int i;
    PHYSICAL_ADDRESS phys = { 0 };
    phys.QuadPart = pyPd;

    PPDE g_pd = (PPDE)MmGetVirtualForPhysical(phys);
    if (!IsValidAddr(g_pd))
        return;
    for (i = 0; i < PAGE_ENTRIES; i++) 
    {
        PDE pde = g_pd[i];

        /* Print flags of this pml4 entry */

        if (PDE_PRESENT(pde.Value)) 
        {
            if (PDE_2MB_PAGE(pde.Value)) 
            {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "PDE_2MB_PAGE\n");
                Int3();
            }
            else {
                /* pde holds the address of a Page Table */
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
                    "PML4[%03d].PDPT[%03d].PDP[%03d].PageFrameNumber : %LX\n",
                    nPml4Index, nPdptIndex, i, pde.PageFrameNumber);
                WalkPt(nPml4Index, nPdptIndex, i, PE_PHYS_ADDR(pde.Value));
            }
        }
        else
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
                "PML4[%03d].PDPT[%03d].PDP[%03d].PageFrameNumber : %LX is not present\n",
                nPml4Index, nPdptIndex, i, pde.PageFrameNumber);

        }
    }
}

void WalkPdpt(int nPml4Index, QWORD* pyPdpt) 
{
    int i;
    PHYSICAL_ADDRESS phys = { 0 };
    phys.QuadPart = pyPdpt;

    g_pdpt = (PPDPTE)MmGetVirtualForPhysical(phys);
    if (!IsValidAddr(g_pdpt))
        return;

    for (i = 0; i < PAGE_ENTRIES; i++) {
        PDPTE pdpte = g_pdpt[i];

        if (pdpte.Present == 1)
        {
            if (PDPTE_1GB_PAGE(pdpte.Value)) 
            {
                //debug("PDPTE_1GB_PAGE\n");
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "PDPTE_1GB_PAGE\n");
            }
            else 
            {
                /* pdpte holds the address of a Page Directory */
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
                    "PML4[%03d].PDPT[%03d].PageFrameNumber : %LX\n",
                    nPml4Index, i, pdpte.PageFrameNumber);
                WalkPd(nPml4Index, i, PE_PHYS_ADDR(pdpte.Value));
            }
        }
        else
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
                "PML4[%03d].PDPT[%03d].PageFrameNumber : %LX is not present\n",
                nPml4Index, i, pdpte.PageFrameNumber);

        }
    }
}

void WalkPml4(QWORD* pyPml4) 
{
    int i;
    PHYSICAL_ADDRESS phys = { 0 };
    phys.QuadPart = pyPml4;
    g_pml4 = (PPML4E)MmGetVirtualForPhysical(phys);
    if (!IsValidAddr(g_pml4))
        return;
    
    for (i = 0; i < PAGE_ENTRIES; i++)
    {
        PML4E pml4e = g_pml4[i];

        /* Print flags of this pml4 entry */
        if (pml4e.Present == 1)
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, 
                "PML4[%03d].PageFrameNumber : %LX\n", i, pml4e.PageFrameNumber);

            WalkPdpt(i, PE_PHYS_ADDR(pml4e.Value));
        }
        else
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
                "PML4[%03d].PageFrameNumber : %LX is not present\n", i, pml4e.PageFrameNumber);

        }
    }
}

void WalkCr3(QWORD cr3)
{

//    QWORD cr3 = ReadCr3();

    //Int3();
    if (PML4_CACHE_DISABLED(cr3)) 
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "PML4 cache DISABLED\n");
    }
    else 
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "PML4 cache ENABLED\n");
        WalkPml4(PE_PHYS_ADDR(cr3));
    }
}


KIRQL WPOFFx64()
{
    KIRQL  irql = KeRaiseIrqlToDpcLevel();
    UINT64  cr0 = __readcr0();
    cr0 &= 0xfffffffffffeffff;
    __writecr0(cr0);
    _disable();
    return  irql;
}

void WPONx64(KIRQL irql)
{
    UINT64 cr0 = __readcr0();
    cr0 |= 0x10000;
    _enable();
    __writecr0(cr0);
    KeLowerIrql(irql);
}

void MyCallGate()
{
    //KeLowerIrql(PASSIVE_LEVEL);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,"Hello MyCallGate\r\n");
    
    Old80();
}


/*
    Remaps the page where the target address is in with PAGE_EXECUTE_READWRITE protection and patches in the given bytes
    If this is the restore routine, then after patching in the bytes the protection is set back to PAGE_READONLY
*/
static BOOLEAN remap_page(  _In_ VOID* address,
                            _In_ BYTE* asm,
                            _In_ ULONG length,
                            _In_ BOOLEAN restore)
{
    MDL* mdl = IoAllocateMdl(address, length, FALSE, FALSE, 0);
    if (!mdl)
    {
        DbgPrint("[-] Failed allocating MDL!\n");
        return FALSE;
    }

    MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);

    VOID* map_address = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, 0, FALSE, NormalPagePriority);
    if (!map_address)
    {
        DbgPrint("[-] Failed mapping the page!\n");
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return FALSE;
    }

    NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
    if (status)
    {
        DbgPrint("[-] Failed MmProtectMdlSystemAddress with status: 0x%lX\n", status);
        MmUnmapLockedPages(map_address, mdl);
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return FALSE;
    }

    RtlCopyMemory(map_address, asm, length);

    if (restore)
    {
        status = MmProtectMdlSystemAddress(mdl, PAGE_READONLY);
        if (status)
        {
            DbgPrint("[-] Failed second MmProtectMdlSystemAddress with status: 0x%lX\n", status);
            MmUnmapLockedPages(map_address, mdl);
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            return FALSE;
        }
    }

    MmUnmapLockedPages(map_address, mdl);
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);

    return TRUE;
}
#define ABSOLUTE(wait) 			(wait)
#define RELATIVE(wait) 			(-(wait))
#define NANOSECONDS(nanos) \
								(((signed __int64)(nanos)) / 100L)
#define MICROSECONDS(micros) \
								(((signed __int64)(micros)) * NANOSECONDS(1000L))
#define MILLISECONDS(milli) \
								(((signed __int64)(milli)) * MICROSECONDS(1000L))
#define SECONDS(seconds) \
								(((signed __int64)(seconds)) * MILLISECONDS(1000L))



NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT   DriverObject,
    _In_ PUNICODE_STRING      RegistryPath
    )
/*++

Routine Description:
    This routine is called by the Operating System to initialize the driver.

    It creates the device object, fills in the dispatch entry points and
    completes the initialization.

Arguments:
    DriverObject - a pointer to the object that represents this device
    driver.

    RegistryPath - a pointer to our Services key in the registry.

Return Value:
    STATUS_SUCCESS if initialized; an error otherwise.

--*/

{
    NTSTATUS        ntStatus;
    UNICODE_STRING  ntUnicodeString;    // NT Device Name "\Device\SIOCTL"
    UNICODE_STRING  ntWin32NameString;    // Win32 Name "\DosDevices\IoctlTest"
    PDEVICE_OBJECT  deviceObject = NULL;    // ptr to device object
    int nIdtCnt = 0;

    UNREFERENCED_PARAMETER(RegistryPath);

    //Int3();

  

    //;DisableWP();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "KeDelayExecutionThread() 1\r\n");

    LARGE_INTEGER x;
    x.QuadPart = RELATIVE(SECONDS(30));; // wait 10 seconds

    KeDelayExecutionThread(KernelMode, FALSE, &x);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "KeDelayExecutionThread() 2\r\n");

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
        "g_idt.Limit : %X\r\ng_idt.Base : %p\r\n", g_idt.Limit, g_idt.Base);

    __sgdt(&g_gdt);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
        "g_gdt.Limit : %X\r\ngdt.Base : %p\r\n", g_gdt.Limit, g_gdt.Base);

    __sidt(&g_idt);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
        "g_idt.Limit : %X\r\ng_idt.Base : %p\r\n", g_idt.Limit, g_idt.Base);

    nIdtCnt = (g_idt.Limit + 1) / 16;
    /*
    typedef struct _IDT_DESCRIPTOR
{
    WORD wOffset1;
    WORD wSelector;

    BYTE bIst : 3; //0-2
    BYTE bReserved1 : 1; //3
    BYTE bReserved2 : 1; //
    BYTE bReserved3 : 3;

    BYTE bType : 4;//8 9 10 11
    BYTE bReserved4 : 1;
    BYTE bDpl : 2;
    BYTE bP : 1;

    WORD wOffset2;
    DWORD dwOffset3;
    DWORD dwReserved;
} IDT_DESCRIPTOR, * PIDT_DESCRIPTOR;
*/
//    for (int i = 0; i < nIdtCnt; i++)
    for (int i = 0; i < nIdtCnt; i++)
    {
        PIDT_DESCRIPTOR pIdtDes = NULL;
        pIdtDes = (PTSSDES)&g_idt.Base[i];
        char* pOffset = (__int64)pIdtDes->dwOffset3 << 32 | (__int64)pIdtDes->wOffset2 << 16 | pIdtDes->wOffset1;
        if (i == 0x80)
            g_pOld80 = pOffset;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "%x =================================================\r\n", i);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "%x : pOffset : %p\r\n", i, pOffset);
//        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "wOffset1 : %X\r\n", pIdtDes->wOffset1);
//        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "wSelector : %X\r\n", pIdtDes->wSelector);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bIst : %X\r\n", pIdtDes->bIst);
//        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bReserved1 : %X\r\n", pIdtDes->bReserved1);
//        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bReserved2 : %X\r\n", pIdtDes->bReserved2);
//        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bReserved3 : %X\r\n", pIdtDes->bReserved3);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bType : %X\r\n", pIdtDes->bType);
//        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bReserved4 : %X\r\n", pIdtDes->bReserved4);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bDpl : %X\r\n", pIdtDes->bDpl);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bP : %X\r\n", pIdtDes->bP);
//        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "wOffset2 : %X\r\n", pIdtDes->wOffset2);
//        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "dwOffset3 : %X\r\n", pIdtDes->dwOffset3);
//        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "dwReserved : %X\r\n", pIdtDes->dwReserved);

    }
    /* IDT Write Test */
    INT64 p = (INT64)MyCallGate;
 //   g_pOld80 = (__int64)g_idt.Base[0x80].dwOffset3 << 32 | (__int64)g_idt.Base[0x80].wOffset2 << 16 | g_idt.Base[0x80].wOffset1;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "g_pOld80 : %p\r\n", g_pOld80);

    /*

    Int3();
    KeSetSystemAffinityThread((KAFFINITY)(1 << 0));
    KIRQL IRQL = WPOFFx64();

    g_idt.Base[0x80].wOffset1 = p & 0x000000000000ffff;
    g_idt.Base[0x80].wOffset2 = (p >> 16) & 0x000000000000ffff;
    g_idt.Base[0x80].dwOffset3 = (p >> 32) & 0x00000000ffffffff;
    WPONx64(IRQL);
    KeRevertToUserAffinityThread();
    */
    /*
    CALLGATEDES stCallGateDes = { 0, };
    stCallGateDes.bType1 = 12; //1100 -> 12
    stCallGateDes.bDpl = 3;
    stCallGateDes.bP = 1;
    
    //옵션을 만들어야 해...
    //:) 옵션을 쪼개야 한다. 
    //:) 3개로...
    //:) 16비트
    p = (INT64)MyCallGate;
    stCallGateDes.wOffset1 = p          & 0x000000000000ffff;
    stCallGateDes.wOffset2 = (p >> 16)  & 0x000000000000ffff;
    stCallGateDes.dwOffset3 = (p >> 32) & 0x00000000ffffffff;

    stCallGateDes.wSelector = 0x10;
    char* p2 = (char*)&g_gdt.Base[5];

    //일단 gdt에 집어 넣지 말자./.;;20210804
    memcpy(p2, &stCallGateDes, 16);


    //nasm_farjmp2es();
   //farjmp2();
     */
    /*typedef struct TssDescriptor
{
    WORD wLimit1;
    WORD wBase1;
    BYTE byBase2;
    BYTE bType : 4;//8-11
    BYTE bReserved1 : 1;
    BYTE bDpl : 2;
    BYTE bP : 1;
    BYTE bLimit2 : 4; //19-16
    BYTE bAvl : 1;
    BYTE bReserved2 : 1;
    BYTE bReserved3 : 1;
    BYTE bG : 1;
    BYTE byBase3;
    DWORD dwBase4;
    BYTE byReserved4;
    BYTE bReserved4 : 5;
    BYTE bReserved5 : 3;
    WORD dwReserved6;
}TSSDES, * PTSSDES;
*/
    /*
    PTSSDES pTssDes = NULL;
    pTssDes = (PTSSDES)&g_gdt.Base[8];
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "TSS for 64bit =================================================\r\n");
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "wLimit1 : %X\r\n", pTssDes->wLimit1);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "wBase1 : %X\r\n", pTssDes->wBase1);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "byBase2 : %X\r\n", pTssDes->byBase2);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bType : %X\r\n", pTssDes->bType);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bReserved1 : %X\r\n", pTssDes->bReserved1);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bDpl : %X\r\n", pTssDes->bDpl);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bP : %X\r\n", pTssDes->bP);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bDpl : %X\r\n", pTssDes->bDpl);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bLimit2 : %X\r\n", pTssDes->bLimit2);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bReserved2 : %X\r\n", pTssDes->bReserved2);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bReserved3 : %X\r\n", pTssDes->bReserved3);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bG : %X\r\n", pTssDes->bG);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "byBase3 : %X\r\n", pTssDes->byBase3);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "dwBase4 : %X\r\n", pTssDes->dwBase4);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "byReserved4 : %X\r\n", pTssDes->byReserved4);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bReserved4 : %X\r\n", pTssDes->bReserved4);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bReserved5 : %X\r\n", pTssDes->bReserved5);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "dwReserved6 : %X\r\n", pTssDes->dwReserved6);
    char* pTssOffset = (__int64)pTssDes->dwBase4 << 32 | (__int64)pTssDes->byBase3 << 24 | (__int64)pTssDes->byBase2 << 16 | pTssDes->wBase1;
    PTSS_64 pTss64 = (PTSS_64)pTssOffset;
    */

    /*
    typedef struct _CR3
{
    QWORD	Ign : 3;
    QWORD	PWT : 1;
    QWORD	PCD : 1;
    QWORD	Ignored : 7;
    QWORD	PML4 : 40;
    QWORD	ReservedMBZ : 12;
}CR3, * PCR3;*/
    CR3 Cr3 = { 0, };
    Cr3.cr3 = ReadCr3();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Cr3.PML4 : %LX\r\n", Cr3.PML4);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Cr3.PWT : %LX\r\n", Cr3.PWT);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Cr3.PCD : %LX\r\n", Cr3.PCD);
    //WalkCr3(Cr3.cr3);
    //g_byOldType = g_gdt.Base[8].Type;

 //   SetClock(250);
    g_due.QuadPart = 1000 * DELAY_ONE_MILLISEC;
    KeInitializeTimer(&g_myTimer);
    KeInitializeDpc(&g_myDpc, MyDpcFunc, NULL);
    KeSetTimer(&g_myTimer, g_due, &g_myDpc);
    
    RtlInitUnicodeString( &ntUnicodeString, NT_DEVICE_NAME );

    ntStatus = IoCreateDevice(
        DriverObject,                   // Our Driver Object
        0,                              // We don't use a device extension
        &ntUnicodeString,               // Device name "\Device\SIOCTL"
        FILE_DEVICE_UNKNOWN,            // Device type
        FILE_DEVICE_SECURE_OPEN,     // Device characteristics
        FALSE,                          // Not an exclusive device
        &deviceObject );                // Returned ptr to Device Object

    if ( !NT_SUCCESS( ntStatus ) )
    {
        SIOCTL_KDPRINT(("Couldn't create the device object\n"));
        return ntStatus;
    }

    //
    // Initialize the driver object with this driver's entry points.
    //

    DriverObject->MajorFunction[IRP_MJ_CREATE] = SioctlCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = SioctlCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SioctlDeviceControl;
    DriverObject->DriverUnload = SioctlUnloadDriver;

    //
    // Initialize a Unicode String containing the Win32 name
    // for our device.
    //

    RtlInitUnicodeString( &ntWin32NameString, DOS_DEVICE_NAME );

    //
    // Create a symbolic link between our device name  and the Win32 name
    //

    ntStatus = IoCreateSymbolicLink(
                        &ntWin32NameString, &ntUnicodeString );

    if ( !NT_SUCCESS( ntStatus ) )
    {
        //
        // Delete everything that this routine has allocated.
        //
        SIOCTL_KDPRINT(("Couldn't create symbolic link\n"));
        IoDeleteDevice( deviceObject );
    }


    return ntStatus;
}


NTSTATUS
SioctlCreateClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
    )
/*++

Routine Description:

    This routine is called by the I/O system when the SIOCTL is opened or
    closed.

    No action is performed other than completing the request successfully.

Arguments:

    DeviceObject - a pointer to the object that represents the device
    that I/O is to be done on.

    Irp - a pointer to the I/O Request Packet for this request.

Return Value:

    NT status code

--*/

{
    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest( Irp, IO_NO_INCREMENT );

    return STATUS_SUCCESS;
}

VOID
SioctlUnloadDriver(
    _In_ PDRIVER_OBJECT DriverObject
    )
/*++

Routine Description:

    This routine is called by the I/O system to unload the driver.

    Any resources previously allocated must be freed.

Arguments:

    DriverObject - a pointer to the object that represents our driver.

Return Value:

    None
--*/

{
    PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;
    UNICODE_STRING uniWin32NameString;

    PAGED_CODE();

    //
    // Create counted string version of our Win32 device name.
    //

    RtlInitUnicodeString( &uniWin32NameString, DOS_DEVICE_NAME );


    //
    // Delete the link from our device name to a name in the Win32 namespace.
    //

    IoDeleteSymbolicLink( &uniWin32NameString );

    if ( deviceObject != NULL )
    {
        IoDeleteDevice( deviceObject );
    }



}

NTSTATUS
SioctlDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
    )

/*++

Routine Description:

    This routine is called by the I/O system to perform a device I/O
    control function.

Arguments:

    DeviceObject - a pointer to the object that represents the device
        that I/O is to be done on.

    Irp - a pointer to the I/O Request Packet for this request.

Return Value:

    NT status code

--*/

{
    PIO_STACK_LOCATION  irpSp;// Pointer to current stack location
    NTSTATUS            ntStatus = STATUS_SUCCESS;// Assume success
    ULONG               inBufLength; // Input buffer length
    ULONG               outBufLength; // Output buffer length
    PCHAR               inBuf, outBuf; // pointer to Input and output buffer
    PCHAR               data = "This String is from Device Driver !!!";
    size_t              datalen = strlen(data)+1;//Length of data including null
    PMDL                mdl = NULL;
    PCHAR               buffer = NULL;

    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    irpSp = IoGetCurrentIrpStackLocation( Irp );
    inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    if (!inBufLength || !outBufLength)
    {
        ntStatus = STATUS_INVALID_PARAMETER;
        goto End;
    }

    //
    // Determine which I/O control code was specified.
    //

    switch ( irpSp->Parameters.DeviceIoControl.IoControlCode )
    {
    case IOCTL_SIOCTL_METHOD_BUFFERED:

        //
        // In this method the I/O manager allocates a buffer large enough to
        // to accommodate larger of the user input buffer and output buffer,
        // assigns the address to Irp->AssociatedIrp.SystemBuffer, and
        // copies the content of the user input buffer into this SystemBuffer
        //

        SIOCTL_KDPRINT(("Called IOCTL_SIOCTL_METHOD_BUFFERED\n"));
        PrintIrpInfo(Irp);

        //
        // Input buffer and output buffer is same in this case, read the
        // content of the buffer before writing to it
        //

        inBuf = Irp->AssociatedIrp.SystemBuffer;
        outBuf = Irp->AssociatedIrp.SystemBuffer;

        //
        // Read the data from the buffer
        //

        SIOCTL_KDPRINT(("\tData from User :"));
        //
        // We are using the following function to print characters instead
        // DebugPrint with %s format because we string we get may or
        // may not be null terminated.
        //
        PrintChars(inBuf, inBufLength);

        //
        // Write to the buffer over-writes the input buffer content
        //

        RtlCopyBytes(outBuf, data, outBufLength);

        SIOCTL_KDPRINT(("\tData to User : "));
        PrintChars(outBuf, datalen  );

        //
        // Assign the length of the data copied to IoStatus.Information
        // of the Irp and complete the Irp.
        //

        Irp->IoStatus.Information = (outBufLength<datalen?outBufLength:datalen);

        //
        // When the Irp is completed the content of the SystemBuffer
        // is copied to the User output buffer and the SystemBuffer is
        // is freed.
        //

       break;

    case IOCTL_SIOCTL_METHOD_NEITHER:

        //
        // In this type of transfer the I/O manager assigns the user input
        // to Type3InputBuffer and the output buffer to UserBuffer of the Irp.
        // The I/O manager doesn't copy or map the buffers to the kernel
        // buffers. Nor does it perform any validation of user buffer's address
        // range.
        //


        SIOCTL_KDPRINT(("Called IOCTL_SIOCTL_METHOD_NEITHER\n"));

        PrintIrpInfo(Irp);

        //
        // A driver may access these buffers directly if it is a highest level
        // driver whose Dispatch routine runs in the context
        // of the thread that made this request. The driver should always
        // check the validity of the user buffer's address range and check whether
        // the appropriate read or write access is permitted on the buffer.
        // It must also wrap its accesses to the buffer's address range within
        // an exception handler in case another user thread deallocates the buffer
        // or attempts to change the access rights for the buffer while the driver
        // is accessing memory.
        //

        inBuf = irpSp->Parameters.DeviceIoControl.Type3InputBuffer;
        outBuf =  Irp->UserBuffer;

        //
        // Access the buffers directly if only if you are running in the
        // context of the calling process. Only top level drivers are
        // guaranteed to have the context of process that made the request.
        //

        try {
            //
            // Before accessing user buffer, you must probe for read/write
            // to make sure the buffer is indeed an userbuffer with proper access
            // rights and length. ProbeForRead/Write will raise an exception if it's otherwise.
            //
            ProbeForRead( inBuf, inBufLength, sizeof( UCHAR ) );

            //
            // Since the buffer access rights can be changed or buffer can be freed
            // anytime by another thread of the same process, you must always access
            // it within an exception handler.
            //

            SIOCTL_KDPRINT(("\tData from User :"));
            PrintChars(inBuf, inBufLength);

        }
        except(EXCEPTION_EXECUTE_HANDLER)
        {

            ntStatus = GetExceptionCode();
            SIOCTL_KDPRINT((
                "Exception while accessing inBuf 0X%08X in METHOD_NEITHER\n",
                            ntStatus));
            break;
        }


        //
        // If you are accessing these buffers in an arbitrary thread context,
        // say in your DPC or ISR, if you are using it for DMA, or passing these buffers to the
        // next level driver, you should map them in the system process address space.
        // First allocate an MDL large enough to describe the buffer
        // and initilize it. Please note that on a x86 system, the maximum size of a buffer
        // that an MDL can describe is 65508 KB.
        //

        mdl = IoAllocateMdl(inBuf, inBufLength,  FALSE, TRUE, NULL);
        if (!mdl)
        {
            ntStatus = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        try
        {

            //
            // Probe and lock the pages of this buffer in physical memory.
            // You can specify IoReadAccess, IoWriteAccess or IoModifyAccess
            // Always perform this operation in a try except block.
            //  MmProbeAndLockPages will raise an exception if it fails.
            //
            MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
        }
        except(EXCEPTION_EXECUTE_HANDLER)
        {

            ntStatus = GetExceptionCode();
            SIOCTL_KDPRINT((
                "Exception while locking inBuf 0X%08X in METHOD_NEITHER\n",
                    ntStatus));
            IoFreeMdl(mdl);
            break;
        }

        //
        // Map the physical pages described by the MDL into system space.
        // Note: double mapping the buffer this way causes lot of
        // system overhead for large size buffers.
        //

        buffer = MmGetSystemAddressForMdlSafe( mdl, NormalPagePriority | MdlMappingNoExecute );

        if (!buffer) {
                ntStatus = STATUS_INSUFFICIENT_RESOURCES;
                MmUnlockPages(mdl);
                IoFreeMdl(mdl);
                break;
        }

        //
        // Now you can safely read the data from the buffer.
        //
        SIOCTL_KDPRINT(("\tData from User (SystemAddress) : "));
        PrintChars(buffer, inBufLength);

        //
        // Once the read is over unmap and unlock the pages.
        //

        MmUnlockPages(mdl);
        IoFreeMdl(mdl);

        //
        // The same steps can be followed to access the output buffer.
        //

        mdl = IoAllocateMdl(outBuf, outBufLength,  FALSE, TRUE, NULL);
        if (!mdl)
        {
            ntStatus = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }


        try {
            //
            // Probe and lock the pages of this buffer in physical memory.
            // You can specify IoReadAccess, IoWriteAccess or IoModifyAccess.
            //

            MmProbeAndLockPages(mdl, UserMode, IoWriteAccess);
        }
        except(EXCEPTION_EXECUTE_HANDLER)
        {

            ntStatus = GetExceptionCode();
            SIOCTL_KDPRINT((
                "Exception while locking outBuf 0X%08X in METHOD_NEITHER\n",
                    ntStatus));
            IoFreeMdl(mdl);
            break;
        }


        buffer = MmGetSystemAddressForMdlSafe( mdl, NormalPagePriority | MdlMappingNoExecute );

        if (!buffer) {
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            ntStatus = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        //
        // Write to the buffer
        //

        RtlCopyBytes(buffer, data, outBufLength);

        SIOCTL_KDPRINT(("\tData to User : %s\n", buffer));
        PrintChars(buffer, datalen);

        MmUnlockPages(mdl);

        //
        // Free the allocated MDL
        //

        IoFreeMdl(mdl);

        //
        // Assign the length of the data copied to IoStatus.Information
        // of the Irp and complete the Irp.
        //

        Irp->IoStatus.Information = (outBufLength<datalen?outBufLength:datalen);

        break;

    case IOCTL_SIOCTL_METHOD_IN_DIRECT:

        //
        // In this type of transfer,  the I/O manager allocates a system buffer
        // large enough to accommodatethe User input buffer, sets the buffer address
        // in Irp->AssociatedIrp.SystemBuffer and copies the content of user input buffer
        // into the SystemBuffer. For the user output buffer, the  I/O manager
        // probes to see whether the virtual address is readable in the callers
        // access mode, locks the pages in memory and passes the pointer to
        // MDL describing the buffer in Irp->MdlAddress.
        //

        SIOCTL_KDPRINT(("Called IOCTL_SIOCTL_METHOD_IN_DIRECT\n"));

        PrintIrpInfo(Irp);

        inBuf = Irp->AssociatedIrp.SystemBuffer;

        SIOCTL_KDPRINT(("\tData from User in InputBuffer: "));
        PrintChars(inBuf, inBufLength);

        //
        // To access the output buffer, just get the system address
        // for the buffer. For this method, this buffer is intended for transfering data
        // from the application to the driver.
        //

        buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);

        if (!buffer) {
            ntStatus = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        SIOCTL_KDPRINT(("\tData from User in OutputBuffer: "));
        PrintChars(buffer, outBufLength);

        //
        // Return total bytes read from the output buffer.
        // Note OutBufLength = MmGetMdlByteCount(Irp->MdlAddress)
        //

        Irp->IoStatus.Information = MmGetMdlByteCount(Irp->MdlAddress);

        //
        // NOTE: Changes made to the  SystemBuffer are not copied
        // to the user input buffer by the I/O manager
        //

      break;

    case IOCTL_SIOCTL_METHOD_OUT_DIRECT:

        //
        // In this type of transfer, the I/O manager allocates a system buffer
        // large enough to accommodate the User input buffer, sets the buffer address
        // in Irp->AssociatedIrp.SystemBuffer and copies the content of user input buffer
        // into the SystemBuffer. For the output buffer, the I/O manager
        // probes to see whether the virtual address is writable in the callers
        // access mode, locks the pages in memory and passes the pointer to MDL
        // describing the buffer in Irp->MdlAddress.
        //


        SIOCTL_KDPRINT(("Called IOCTL_SIOCTL_METHOD_OUT_DIRECT\n"));

        PrintIrpInfo(Irp);


        inBuf = Irp->AssociatedIrp.SystemBuffer;

        SIOCTL_KDPRINT(("\tData from User : "));
        PrintChars(inBuf, inBufLength);

        //
        // To access the output buffer, just get the system address
        // for the buffer. For this method, this buffer is intended for transfering data
        // from the driver to the application.
        //

        buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);

        if (!buffer) {
            ntStatus = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        //
        // Write data to be sent to the user in this buffer
        //

        RtlCopyBytes(buffer, data, outBufLength);

        SIOCTL_KDPRINT(("\tData to User : "));
        PrintChars(buffer, datalen);

        Irp->IoStatus.Information = (outBufLength<datalen?outBufLength:datalen);

        //
        // NOTE: Changes made to the  SystemBuffer are not copied
        // to the user input buffer by the I/O manager
        //

        break;
    case IOCTL_TEST_001:
    {
        //0018 00000000`00000000 00000000`00000000 Data RW Ac 0 Bg By P  Nl 00000493
        g_gdt.Base[4].SegmentLimitHigh = 0x00;
        g_gdt.Base[4].SegmentLimitLow = 0x0000;
        g_gdt.Base[5].SegmentLimitHigh = 0x00;
        g_gdt.Base[5].SegmentLimitLow = 0x0000;

        break;
    }
    case IOCTL_TEST_002:
    {
        //0018 00000000`00000000 00000000`00000000 Data RW Ac 0 Bg By P  Nl 00000493
        g_gdt.Base[4].SegmentLimitHigh = 0xff;
        g_gdt.Base[4].SegmentLimitLow = 0xffff;
        g_gdt.Base[5].SegmentLimitHigh = 0xff;
        g_gdt.Base[5].SegmentLimitLow = 0xffff;

        break;
    }
    case IOCTL_TEST_003:
    {
        int nCnt = (g_gdt.Limit + 1) / 8;
        for (int i = 0; i < nCnt; i++)
        {

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[%d]=================================================\r\n", i);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "SegmentLimitLow : %X\r\n", g_gdt.Base[i].SegmentLimitLow);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "BaseAddressLow : %X\r\n", g_gdt.Base[i].BaseAddressLow);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "BaseAddressMid : %X\r\n", g_gdt.Base[i].BaseAddressMid);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Type : %X\r\n", g_gdt.Base[i].Type);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "DescriptorType : %X\r\n", g_gdt.Base[i].DescriptorType);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "DPL : %X\r\n", g_gdt.Base[i].DPL);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Present : %X\r\n", g_gdt.Base[i].Present);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "SegmentLimitHigh : %X\r\n", g_gdt.Base[i].SegmentLimitHigh);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "AVL : %X\r\n", g_gdt.Base[i].AVL);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "L : %X\r\n", g_gdt.Base[i].L);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "D_B : %X\r\n", g_gdt.Base[i].D_B);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "G : %X\r\n", g_gdt.Base[i].G);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "BaseAddressHigh : %X\r\n", g_gdt.Base[i].BaseAddressHigh);
        }
        // 8번재.. tss를 찍어보자...
        /*
        * typedef struct TssDescriptor
{
    WORD wLimit1;
    WORD wBase1;
    BYTE byBase2;
    BYTE bType : 4;//8-11
    BYTE bReserved1 : 1;
    BYTE bDpl : 2;
    BYTE bP : 1;
    BYTE bLimit2:4; //19-16
    BYTE bAvl : 1;
    BYTE bReserved2 : 1;
    BYTE bReserved3 : 1;
    BYTE bG : 1;
    BYTE byBase3;
    DWORD dwBase4;
    BYTE byReserved4;
    BYTE bReserved4 : 5;
    BYTE bReserved5 : 3;
    WORD dwReserved6;
}TSSDES, * PTSSDES;
        */
        PTSSDES pTssDes = NULL;
        pTssDes = (PTSSDES)&g_gdt.Base[8];
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "TSS for 64bit =================================================\r\n");
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "wLimit1 : %X\r\n", pTssDes->wLimit1);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "wBase1 : %X\r\n", pTssDes->wBase1);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bType : %X\r\n", pTssDes->bType);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bReserved1 : %X\r\n", pTssDes->bReserved1);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bDpl : %X\r\n", pTssDes->bDpl);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bP : %X\r\n", pTssDes->bP);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bDpl : %X\r\n", pTssDes->bDpl);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bLimit2 : %X\r\n", pTssDes->bLimit2);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bReserved2 : %X\r\n", pTssDes->bReserved2);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bReserved3 : %X\r\n", pTssDes->bReserved3);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bG : %X\r\n", pTssDes->bG);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "byBase3 : %X\r\n", pTssDes->byBase3);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "dwBase4 : %X\r\n", pTssDes->dwBase4);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "byReserved4 : %X\r\n", pTssDes->byReserved4);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bReserved4 : %X\r\n", pTssDes->bReserved4);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "bReserved5 : %X\r\n", pTssDes->bReserved5);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "dwReserved6 : %X\r\n", pTssDes->dwReserved6);

        break;
    }
    case IOCTL_TEST_004:
    {
        //0018 00000000`00000000 00000000`00000000 Data RW Ac 0 Bg By P  Nl 00000493
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "g_gdt.Base[8].Type = 0\r\n");
        g_gdt.Base[8].Type = 0;
        //g_gdt.Base[5].SegmentLimitHigh = 0;
        break;
    }
    case IOCTL_TEST_005:
    {
        //0018 00000000`00000000 00000000`00000000 Data RW Ac 0 Bg By P  Nl 00000493
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "g_gdt.Base[4].DPL = 3;\r\n");
        g_gdt.Base[6].DPL = 3;
        // g_gdt.Base[5].SegmentLimitHigh = 0xff;
        break;
    }
    case IOCTL_TEST_006:
    {
        {
            DWORD dwPid = 0;
            DWORD64 targetEPROC = 0;
            inBuf = Irp->AssociatedIrp.SystemBuffer;
            dwPid = *(DWORD*)inBuf;

            targetEPROC = FindProcessEPROC(dwPid);

            if (targetEPROC == 0)
                KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nPID not Found\n\n"));
            else {
                KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nFound EPROCESS : 0x%llx\n\n", targetEPROC));
                //Get CR3
                QWORD cr3 = GetProcessDirBase(targetEPROC);
                WalkCr3(cr3);

            }
        }
        outBuf = Irp->AssociatedIrp.SystemBuffer;

        //
        // Read the data from the buffer
        //

        SIOCTL_KDPRINT(("\tData from User :"));
        //
        // We are using the following function to print characters instead
        // DebugPrint with %s format because we string we get may or
        // may not be null terminated.
        //
 //       PrintChars(inBuf, inBufLength);

        //
        // Write to the buffer over-writes the input buffer content
        //

        RtlCopyBytes(outBuf, data, outBufLength);

        SIOCTL_KDPRINT(("\tData to User : "));
  //      PrintChars(outBuf, datalen);

        //
        // Assign the length of the data copied to IoStatus.Information
        // of the Irp and complete the Irp.
        //

        Irp->IoStatus.Information = (outBufLength < datalen ? outBufLength : datalen);

        //
        // When the Irp is completed the content of the SystemBuffer
        // is copied to the User output buffer and the SystemBuffer is
        // is freed.
        //



        /*
        PTSS_32 pTss32 = NULL:
        DWORD dwBase = 0;
        //0018 00000000`00000000 00000000`00000000 Data RW Ac 0 Bg By P  Nl 00000493
        //TSS32 의 base값을 만들자 

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "BaseAddressLow : %X\r\n", g_gdt.Base[i].BaseAddressLow);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "BaseAddressMid : %X\r\n", g_gdt.Base[i].BaseAddressMid);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "BaseAddressHigh : %X\r\n", g_gdt.Base[i].BaseAddressHigh);
        dwBase = g_gdt[8].BaseAddressHigh << 24 | g_pcgd_base[8].BaseAddressMid << 16 | g_pcgd_base[8].BaseAddressLow;
        */
        break;
    }
    default:

        //
        // The specified I/O control code is unrecognized by this driver.
        //

        ntStatus = STATUS_INVALID_DEVICE_REQUEST;
        SIOCTL_KDPRINT(("ERROR: unrecognized IOCTL %x\n",
            irpSp->Parameters.DeviceIoControl.IoControlCode));
        break;
    }

End:
    //
    // Finish the I/O operation by simply completing the packet and returning
    // the same status as in the packet itself.
    //

    Irp->IoStatus.Status = ntStatus;

    IoCompleteRequest( Irp, IO_NO_INCREMENT );

    return ntStatus;
}

VOID
PrintIrpInfo(
    PIRP Irp)
{
    PIO_STACK_LOCATION  irpSp;
    irpSp = IoGetCurrentIrpStackLocation( Irp );

    PAGED_CODE();

    SIOCTL_KDPRINT(("\tIrp->AssociatedIrp.SystemBuffer = 0x%p\n",
        Irp->AssociatedIrp.SystemBuffer));
    SIOCTL_KDPRINT(("\tIrp->UserBuffer = 0x%p\n", Irp->UserBuffer));
    SIOCTL_KDPRINT(("\tirpSp->Parameters.DeviceIoControl.Type3InputBuffer = 0x%p\n",
        irpSp->Parameters.DeviceIoControl.Type3InputBuffer));
    SIOCTL_KDPRINT(("\tirpSp->Parameters.DeviceIoControl.InputBufferLength = %d\n",
        irpSp->Parameters.DeviceIoControl.InputBufferLength));
    SIOCTL_KDPRINT(("\tirpSp->Parameters.DeviceIoControl.OutputBufferLength = %d\n",
        irpSp->Parameters.DeviceIoControl.OutputBufferLength ));
    return;
}

VOID
PrintChars(
    _In_reads_(CountChars) PCHAR BufferAddress,
    _In_ size_t CountChars
    )
{
    PAGED_CODE();

    if (CountChars) {

        while (CountChars--) {

            if (*BufferAddress > 31
                 && *BufferAddress != 127) {

                KdPrint (( "%c", *BufferAddress) );

            } else {

                KdPrint(( ".") );

            }
            BufferAddress++;
        }
        KdPrint (("\n"));
    }
    return;
}



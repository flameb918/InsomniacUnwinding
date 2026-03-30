// sleepmask based on Ekko 

#include <windows.h>
#include <stdio.h>

typedef struct {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING;

VOID CALLBACK CaptureThreadId(PVOID lpParameter, BOOLEAN TimerOrWaitFired) {
    printf("[*] Timer thread ID: %lu\n", GetCurrentThreadId());
}

// UNWIND_INFO flags
#define UNW_FLAG_NHANDLER  0x0
#define UNW_FLAG_EHANDLER  0x1
#define UNW_FLAG_UHANDLER  0x2
#define UNW_FLAG_CHAININFO 0x4

// UNWIND_INFO structure 
typedef struct _UNWIND_INFO {
    BYTE VersionAndFlags;
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegisterAndOffset;
    // UNWIND_CODE UnwindCode[]; // Variable length array follows
} UNWIND_INFO, * PUNWIND_INFO;

typedef struct _PRESERVE_REGION {
    ULONG_PTR RVA;
    DWORD     Size;
    PBYTE     SavedCopy;
} PRESERVE_REGION, * PPRESERVE_REGION;

// Forward declarations
DWORD CalculateUnwindInfoSize(PBYTE pImage, DWORD unwindInfoRVA);
BOOL FindUnwindInfoRegions(PBYTE pImage, PRESERVE_REGION* regions, DWORD* count, DWORD maxRegions);

// create dead beef signatures for yara
// .rdata signature 
const char DeadBeefSigRdata[] = { 0xDE, 0xAD, 0xBE, 0xEF };

// .data signature 
volatile char DeadBeefSigdata[] = { 0xDE, 0xAD, 0xBE, 0xEF };

#define MAX_UNWIND_REGIONS 64

VOID EkkoObf(DWORD SleepTime)
{
    CONTEXT CtxThread = { 0 };
    CONTEXT RopProtRW = { 0 };
    CONTEXT RopMemEnc = { 0 };
    CONTEXT RopDelay = { 0 };
    CONTEXT RopMemDec = { 0 };
    CONTEXT RopProtRX = { 0 };
    CONTEXT RopSetEvt = { 0 };
    CONTEXT PdataPatch = { 0 };
    CONTEXT PdataPatch2 = { 0 };
    CONTEXT HeaderPatch1 = { 0 };
    CONTEXT HeaderPatch2 = { 0 };

    // Surgical UNWIND_INFO patch contexts
    CONTEXT UnwindPatch1[MAX_UNWIND_REGIONS] = { 0 };  // pre-sleep patches
    CONTEXT UnwindPatch2[MAX_UNWIND_REGIONS] = { 0 };  // post-decrypt patches
    PRESERVE_REGION UnwindRegions[MAX_UNWIND_REGIONS] = { 0 };
    DWORD UnwindRegionCount = 0;

    HANDLE    hTimerQueue = NULL;
    HANDLE    hNewTimer = NULL;
    HANDLE    hEvent = NULL;
    ULONG_PTR ImageBase = 0;
    DWORD     ImageSize = 0;
    DWORD     OldProtect = 0;

    CHAR    KeyBuf[16] = { 0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
                           0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55 };
    USTRING Key = { 0 };
    USTRING Img = { 0 };

    PVOID NtContinue = NULL;
    PVOID SysFunc032 = NULL;
    PVOID pRtlCopyMemory = NULL;

    hEvent = CreateEventW(0, 0, 0, 0);
    hTimerQueue = CreateTimerQueue();

    NtContinue = GetProcAddress(GetModuleHandleA("ntdll"), "NtContinue");
    SysFunc032 = GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");
    pRtlCopyMemory = GetProcAddress(GetModuleHandleA("ntdll"), "RtlCopyMemory");

    ImageBase = (ULONG_PTR)GetModuleHandleA(NULL);
    ImageSize = ((PIMAGE_NT_HEADERS)(ImageBase +
        ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew))
        ->OptionalHeader.SizeOfImage;

    // Get PE headers info
    PIMAGE_NT_HEADERS    pNtHdrs = (PIMAGE_NT_HEADERS)(ImageBase +
        ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHdrs);

    // Get the headers
    DWORD HeaderSize = pNtHdrs->OptionalHeader.SizeOfHeaders;
    PBYTE SavedHeaders = (PBYTE)HeapAlloc(GetProcessHeap(), 0, HeaderSize);
    memcpy(SavedHeaders, (PVOID)ImageBase, HeaderSize);

    // Find .pdata section and save a copy
    ULONG_PTR PdataBase = 0;
    PBYTE SavedPdata = NULL;
    DWORD PdataSize = 0;

    for (WORD i = 0; i < pNtHdrs->FileHeader.NumberOfSections; i++) {
        if (memcmp(pSection[i].Name, ".pdata\0\0", 8) == 0) {
            PdataBase = ImageBase + pSection[i].VirtualAddress;
            PdataSize = pSection[i].Misc.VirtualSize;
            SavedPdata = (PBYTE)HeapAlloc(GetProcessHeap(), 0, PdataSize);
            memcpy(SavedPdata, (PVOID)PdataBase, PdataSize);
            break;
        }
    }

    // Find .rdata for size comparison only
    ULONG_PTR RdataBase = 0;
    DWORD RdataSize = 0;
    for (WORD i = 0; i < pNtHdrs->FileHeader.NumberOfSections; i++) {
        if (memcmp(pSection[i].Name, ".rdata\0\0", 8) == 0) {
            RdataBase = ImageBase + pSection[i].VirtualAddress;
            RdataSize = pSection[i].Misc.VirtualSize;
            break;
        }
    }

    // SURGICAL: Find only the UNWIND_INFO regions we need (not full .rdata)
    if (!FindUnwindInfoRegions((PBYTE)ImageBase, UnwindRegions, &UnwindRegionCount, MAX_UNWIND_REGIONS)) {
        puts("[ERROR] Failed to find UNWIND_INFO regions");
        return;
    }

    // Save copies of each UNWIND_INFO region
    DWORD totalUnwindBytes = 0;
    for (DWORD i = 0; i < UnwindRegionCount; i++) {
        UnwindRegions[i].SavedCopy = (PBYTE)HeapAlloc(GetProcessHeap(), 0, UnwindRegions[i].Size);
        memcpy(UnwindRegions[i].SavedCopy, (PBYTE)(ImageBase + UnwindRegions[i].RVA), UnwindRegions[i].Size);
        totalUnwindBytes += UnwindRegions[i].Size;
    }
    printf("[+] Surgical extraction: %lu bytes vs full .rdata: %lu bytes (%.1f%% reduction)\n",
        totalUnwindBytes, RdataSize, 100.0 - ((double)totalUnwindBytes / RdataSize * 100.0));

    printf("[DEBUG] NtContinue:     %p\n", NtContinue);
    printf("[DEBUG] SysFunc032:     %p\n", SysFunc032);
    printf("[DEBUG] pRtlCopyMemory: %p\n", pRtlCopyMemory);
    printf("[DEBUG] ImageBase:      %p  ImageSize: %lu\n", (PVOID)ImageBase, ImageSize);
    printf("[DEBUG] HeaderSize:     %lu\n", HeaderSize);
    printf("[DEBUG] PdataBase:      %p  PdataSize: %lu\n", (PVOID)PdataBase, PdataSize);

    if (!NtContinue || !SysFunc032 || !pRtlCopyMemory ||
        PdataBase == 0 || PdataSize == 0 || !SavedPdata || UnwindRegionCount == 0) {
        puts("[ERROR] Setup failed");
        return;
    }

    Key.Buffer = KeyBuf;
    Key.Length = Key.MaximumLength = 16;

    Img.Buffer = (PVOID)ImageBase;
    Img.Length = Img.MaximumLength = ImageSize;

    if (CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)RtlCaptureContext,
        &CtxThread, 0, 0, WT_EXECUTEINTIMERTHREAD))
    {
        WaitForSingleObject(hEvent, 0x32);

        // Initialize base contexts
        memcpy(&RopProtRW, &CtxThread, sizeof(CONTEXT));
        memcpy(&RopMemEnc, &CtxThread, sizeof(CONTEXT));
        memcpy(&RopDelay, &CtxThread, sizeof(CONTEXT));
        memcpy(&RopMemDec, &CtxThread, sizeof(CONTEXT));
        memcpy(&RopProtRX, &CtxThread, sizeof(CONTEXT));
        memcpy(&RopSetEvt, &CtxThread, sizeof(CONTEXT));
        memcpy(&PdataPatch, &CtxThread, sizeof(CONTEXT));
        memcpy(&PdataPatch2, &CtxThread, sizeof(CONTEXT));
        memcpy(&HeaderPatch1, &CtxThread, sizeof(CONTEXT));
        memcpy(&HeaderPatch2, &CtxThread, sizeof(CONTEXT));

        // Initialize surgical UNWIND_INFO patch contexts
        for (DWORD i = 0; i < UnwindRegionCount; i++) {
            memcpy(&UnwindPatch1[i], &CtxThread, sizeof(CONTEXT));
            memcpy(&UnwindPatch2[i], &CtxThread, sizeof(CONTEXT));

            // Pre-sleep patch: restore this UNWIND_INFO region
            UnwindPatch1[i].Rsp -= 8;
            UnwindPatch1[i].Rip = (DWORD64)pRtlCopyMemory;
            UnwindPatch1[i].Rcx = ImageBase + UnwindRegions[i].RVA;
            UnwindPatch1[i].Rdx = (DWORD64)UnwindRegions[i].SavedCopy;
            UnwindPatch1[i].R8 = UnwindRegions[i].Size;

            // Post-decrypt patch: restore this UNWIND_INFO region again
            UnwindPatch2[i].Rsp -= 8;
            UnwindPatch2[i].Rip = (DWORD64)pRtlCopyMemory;
            UnwindPatch2[i].Rcx = ImageBase + UnwindRegions[i].RVA;
            UnwindPatch2[i].Rdx = (DWORD64)UnwindRegions[i].SavedCopy;
            UnwindPatch2[i].R8 = UnwindRegions[i].Size;
        }

        // 1. VirtualProtect -> RW
        RopProtRW.Rsp -= 8;
        RopProtRW.Rip = (DWORD64)VirtualProtect;
        RopProtRW.Rcx = ImageBase;
        RopProtRW.Rdx = ImageSize;
        RopProtRW.R8 = PAGE_READWRITE;
        RopProtRW.R9 = (DWORD64)&OldProtect;

        // 2. SystemFunction032 - encrypt
        RopMemEnc.Rsp -= 8;
        RopMemEnc.Rip = (DWORD64)SysFunc032;
        RopMemEnc.Rcx = (DWORD64)&Img;
        RopMemEnc.Rdx = (DWORD64)&Key;

        // 3. Restore the headers
        HeaderPatch1.Rsp -= 8;
        HeaderPatch1.Rip = (DWORD64)pRtlCopyMemory;
        HeaderPatch1.Rcx = ImageBase;
        HeaderPatch1.Rdx = (DWORD64)SavedHeaders;
        HeaderPatch1.R8 = HeaderSize;

        // 4. Patch .pdata back
        PdataPatch.Rsp -= 8;
        PdataPatch.Rip = (DWORD64)pRtlCopyMemory;
        PdataPatch.Rcx = PdataBase;
        PdataPatch.Rdx = (DWORD64)SavedPdata;
        PdataPatch.R8 = PdataSize;

        // 5. (Surgical UNWIND_INFO patches queued dynamically below)

        // 6. Sleep
        RopDelay.Rsp -= 8;
        RopDelay.Rip = (DWORD64)WaitForSingleObject;
        RopDelay.Rcx = (DWORD64)-1;
        RopDelay.Rdx = SleepTime;

        // 7. SystemFunction032 - decrypt
        RopMemDec.Rsp -= 8;
        RopMemDec.Rip = (DWORD64)SysFunc032;
        RopMemDec.Rcx = (DWORD64)&Img;
        RopMemDec.Rdx = (DWORD64)&Key;

        // 8. Restore plaintext headers again
        HeaderPatch2.Rsp -= 8;
        HeaderPatch2.Rip = (DWORD64)pRtlCopyMemory;
        HeaderPatch2.Rcx = ImageBase;
        HeaderPatch2.Rdx = (DWORD64)SavedHeaders;
        HeaderPatch2.R8 = HeaderSize;

        // 9. Patch .pdata back again
        PdataPatch2.Rsp -= 8;
        PdataPatch2.Rip = (DWORD64)pRtlCopyMemory;
        PdataPatch2.Rcx = PdataBase;
        PdataPatch2.Rdx = (DWORD64)SavedPdata;
        PdataPatch2.R8 = PdataSize;

        // 10. (Surgical UNWIND_INFO patches queued dynamically below)

        // 11. VirtualProtect -> RX
        RopProtRX.Rsp -= 8;
        RopProtRX.Rip = (DWORD64)VirtualProtect;
        RopProtRX.Rcx = ImageBase;
        RopProtRX.Rdx = ImageSize;
        RopProtRX.R8 = PAGE_EXECUTE_READ;
        RopProtRX.R9 = (DWORD64)&OldProtect;

        // 12. SetEvent
        RopSetEvt.Rsp -= 8;
        RopSetEvt.Rip = (DWORD64)SetEvent;
        RopSetEvt.Rcx = (DWORD64)hEvent;

        puts("[INFO] Queuing timers...");

        // Calculate dynamic timing based on number of regions
        DWORD t = 50;  // starting offset in ms 

		CreateTimerQueueTimer(&hNewTimer, hTimerQueue, CaptureThreadId, NULL, t, 0, WT_EXECUTEINTIMERTHREAD); //used to get the thread id to analyze the call stack of the timers 
        t += 50;

        // VirtualProtect -> RW
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopProtRW, t, 0, WT_EXECUTEINTIMERTHREAD);
        t += 50;

        // Encrypt
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopMemEnc, t, 0, WT_EXECUTEINTIMERTHREAD);
        t += 50;

        // Restore headers
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &HeaderPatch1, t, 0, WT_EXECUTEINTIMERTHREAD);
        t += 50;

        // Restore .pdata
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &PdataPatch, t, 0, WT_EXECUTEINTIMERTHREAD);
        t += 50;

        // Restore each UNWIND_INFO region (surgical patches)
        for (DWORD i = 0; i < UnwindRegionCount; i++) {
            CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue,
                &UnwindPatch1[i], t, 0, WT_EXECUTEINTIMERTHREAD);
            t += 10;  // small gap between patches
        }
        t += 40;  // extra gap before sleep

        // Sleep
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopDelay, t, 0, WT_EXECUTEINTIMERTHREAD);
        t += 100;

        // Decrypt
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopMemDec, t, 0, WT_EXECUTEINTIMERTHREAD);
        t += 50;

        // Restore headers again
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &HeaderPatch2, t, 0, WT_EXECUTEINTIMERTHREAD);
        t += 50;

        // Restore .pdata again
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &PdataPatch2, t, 0, WT_EXECUTEINTIMERTHREAD);
        t += 50;

        // Restore each UNWIND_INFO region again (surgical patches)
        for (DWORD i = 0; i < UnwindRegionCount; i++) {
            CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue,
                &UnwindPatch2[i], t, 0, WT_EXECUTEINTIMERTHREAD);
            t += 10;
        }
        t += 40;

        // VirtualProtect -> RX
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopProtRX, t, 0, WT_EXECUTEINTIMERTHREAD);
        t += 50;

        // SetEvent
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopSetEvt, t, 0, WT_EXECUTEINTIMERTHREAD);

        printf("[INFO] Total timer chain: %lu ms + %lu ms sleep\n", t, SleepTime);

        puts("[INFO] Waiting for cycle to complete...");
        WaitForSingleObject(hEvent, INFINITE);
        puts("[INFO] Cycle complete");
    }

    // Cleanup
    HeapFree(GetProcessHeap(), 0, SavedHeaders);
    HeapFree(GetProcessHeap(), 0, SavedPdata);
    for (DWORD i = 0; i < UnwindRegionCount; i++) {
        if (UnwindRegions[i].SavedCopy) {
            HeapFree(GetProcessHeap(), 0, UnwindRegions[i].SavedCopy);
        }
    }
    DeleteTimerQueue(hTimerQueue);
}

/*---------------------------------------------------------------------------------------------------------------------------*/

// Surgical byte preservation (the same as the cross-process POC) - Calculate the total size of an UNWIND_INFO structure including variable parts

DWORD CalculateUnwindInfoSize(PBYTE pImage, DWORD unwindInfoRVA) {
    PUNWIND_INFO pUnwind = (PUNWIND_INFO)(pImage + unwindInfoRVA);

    BYTE version = pUnwind->VersionAndFlags & 0x7;
    BYTE flags = (pUnwind->VersionAndFlags >> 3) & 0x1F;
    BYTE countOfCodes = pUnwind->CountOfCodes;

    // Base size: 4 bytes header
    DWORD size = sizeof(UNWIND_INFO);

    // Add UnwindCode array: each UNWIND_CODE is 2 bytes
    size += countOfCodes * sizeof(USHORT);

    // Align to DWORD boundary (UnwindCode count must be even for alignment)
    if (countOfCodes % 2 != 0) {
        size += sizeof(USHORT);
    }

    // Check for chained unwind info or exception handler
    if (flags & UNW_FLAG_CHAININFO) {
        // Chained RUNTIME_FUNCTION follows
        size += sizeof(RUNTIME_FUNCTION);
    }
    else if (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) {
        // Exception handler RVA follows (and possibly handler data)
        size += sizeof(DWORD); // Handler RVA
    }

    return size;
}

// Find all UNWIND_INFO regions referenced by .pdata
BOOL FindUnwindInfoRegions(PBYTE pImage, PRESERVE_REGION* regions, DWORD* count, DWORD maxRegions) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pImage;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pImage + pDos->e_lfanew);

    // Get Exception Directory (points to .pdata)
    DWORD pdataRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    DWORD pdataSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;

    if (pdataRVA == 0 || pdataSize == 0) {
        puts("[!] No exception directory found");
        return FALSE;
    }

    PRUNTIME_FUNCTION pRuntimeFuncs = (PRUNTIME_FUNCTION)(pImage + pdataRVA);
    DWORD numFuncs = pdataSize / sizeof(RUNTIME_FUNCTION);

    printf("[+] Found %lu RUNTIME_FUNCTION entries in .pdata\n", numFuncs);

    *count = 0;

    // Track unique UNWIND_INFO addresses (some functions may share)
    DWORD seenAddresses[256] = { 0 };
    DWORD seenCount = 0;

    for (DWORD i = 0; i < numFuncs && *count < maxRegions; i++) {
        DWORD unwindRVA = pRuntimeFuncs[i].UnwindInfoAddress;

        // Check if we've already added this UNWIND_INFO
        BOOL alreadySeen = FALSE;
        for (DWORD j = 0; j < seenCount; j++) {
            if (seenAddresses[j] == unwindRVA) {
                alreadySeen = TRUE;
                break;
            }
        }

        if (!alreadySeen && seenCount < 256) {
            DWORD unwindSize = CalculateUnwindInfoSize(pImage, unwindRVA);

            regions[*count].RVA = unwindRVA;
            regions[*count].Size = unwindSize;
            regions[*count].SavedCopy = NULL;

            seenAddresses[seenCount++] = unwindRVA;
            (*count)++;
        }
    }

    printf("[+] Found %lu unique UNWIND_INFO structures to preserve\n", *count);

    return (*count > 0);
}

int main() {

    // Use the arrays to create dead beef signatures in the binary for yara
    char a = DeadBeefSigRdata[0];
    char b = DeadBeefSigdata[0];
    int ProcessId = GetCurrentProcessId();
    printf("[YARA] scan for yara now, everything is unencrypted. Process ID: %lu\n", ProcessId);
    puts("[DEBUG] attach a debugger now then press enter...");
    getchar();
    puts("[INFO] Sleeping...");
    while (TRUE) {
        EkkoObf(10000);
        puts("[*] Click me to continue...");
        getchar();
    }
    return 0;
}
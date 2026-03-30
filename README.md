# InsomniacUnwinding

Surgical UNWIND_INFO preservation for sleep masking without call stack spoofing.

**Blog Post:** [Unwind Data Can't Sleep - Introducing InsomniacUnwinding](https://lorenzomeacci.com/unwind-data-cant-sleep-introducing-insomniacunwinding)

## Overview

Traditional sleep masking encrypts the entire payload image, breaking stack unwinding. This implementation is based on Ekko created by (@C5pider) and surgically preserve only the UNWIND_INFO structures needed for stack walking (~250 bytes vs ~6KB full `.rdata`), the PE Headers and the .pdata section.

## How It Works

The timer chain is extended to patch back preserved regions after encryption:

1. `VirtualProtect` → RW
2. `SystemFunction032` → Encrypt entire image
3. `RtlCopyMemory` → Restore PE headers
4. `RtlCopyMemory` → Restore .pdata
5. `RtlCopyMemory` × N → Restore each UNWIND_INFO region
6. `WaitForSingleObject` → Sleep
7. `SystemFunction032` → Decrypt
8. `RtlCopyMemory` → Restore PE headers (XOR'd to garbage)
9. `RtlCopyMemory` → Restore .pdata
10. `RtlCopyMemory` × N → Restore each UNWIND_INFO region
11. `VirtualProtect` → RX
12. `SetEvent` → Signal completion

## Usage

1. Build in Visual Studio (x64 Release)

2. Run:
```
.\InsomniacUnwinding.exe
```

3. Attach a debugger and inspect the main thread's call stack during sleep. It should resolve correctly through `BaseThreadInitThunk` and `RtlUserThreadStart`.

## YARA Testing

Test signatures are embedded in `.rdata` and `.data`:
```
.\yara64.exe DeadBeefSignature.yar <pid>
```

Expected results:
- **Awake:** 2 hits
- **Sleeping:** 0 hits (both encrypted, only UNWIND_INFO preserved)

## Key Insight

Call stack spoofing is an architectural consequence of unbacked sleepmask memory, not a fundamental requirement. When the sleepmask executes from backed memory, spoofing becomes unnecessary.

## Acknowledgments

Thanks to Alex Reid (@Octoberfest73) for catching a mistake in the initial research that led to this improved implementation.
# Methodology

## Research Overview

This document describes the step-by-step methodology used to extract and analyze Intel Management Engine firmware from a live system. The research was conducted on a Lenovo IdeaPad Gaming 3 15IAH7 (82S9) with Intel Core i7-12650H (Alder Lake).

## Prerequisites

### Hardware
- Target laptop with Intel 12th Gen (Alder Lake) processor
- Administrator access to the target system
- No additional hardware required (software-only extraction)

### Software
- Windows 10/11 with administrator privileges
- Intel CSME System Tools v16.1
- MEAnalyzer v1.311.0
- Python 3.x
- Radare2 6.1.8 (optional, for disassembly)

## Phase 1: System Identification

### Step 1.1: Identify the target system
```powershell
# System information
systeminfo | findstr /C:"OS Name" /C:"System Model" /C:"System Manufacturer"

# BIOS version
wmic bios get smbiosbiosversion

# CPU identification
wmic cpu get name
```

**Result:** Lenovo IdeaPad Gaming 3 15IAH7, Intel Core i7-12650H, BIOS JMCN48WW

### Step 1.2: Identify the ME hardware
```powershell
# Find Intel MEI device on PCI bus
wmic path Win32_PnPEntity where "DeviceID like '%VEN_8086%DEV_51E0%'" get Name, DeviceID
```

**Result:** PCI\VEN_8086&DEV_51E0 at Bus 22, Device 0, Function 0

### Step 1.3: Check ME status
```powershell
# Run MEInfo as administrator
MEInfoWin64_v16.1.exe -verbose
```

**Key findings from MEInfo:**
- ME firmware version: 16.0.15.1735
- FPF (Fused Protection Fuses): Committed (permanent)
- PCH Unlocked: Disabled
- Flash Protection: Protected
- BootGuard Profile: 3 (Full Verified Boot)

## Phase 2: ME Firmware Extraction

### Step 2.1: Identify flash layout
```powershell
# Use Flash Programming Tool to identify regions
FPTW64_v16.1.exe -summary
```

### Step 2.2: Dump ME region
```powershell
# Extract ME region from live SPI flash
FPTW64_v16.1.exe -D ME_region.bin -ME
```

**Result:** 4,943,872 bytes (4,711 KB) extracted successfully

### Step 2.3: Verify dump integrity
```powershell
# Run manufacturing tests to verify hardware state
MEManufWin64_v16.1.exe -verbose
```

**Result:** All 10 hardware self-tests passed

## Phase 3: Firmware Structure Analysis

### Step 3.1: Locate Flash Partition Table (FPT)
```
Search for signature: $FPT (hex: 24 46 50 54)
Found at ME offset: 0x216000
Header type: 0x0D
Entry version: 0x00
```

### Step 3.2: Parse FPT entries
```
For each entry:
- Read 4-byte partition name (ASCII)
- Read 4-byte offset (little-endian)
- Read 4-byte length (little-endian)
- Calculate end address and verify bounds
```

### Step 3.3: Locate Code Partition Directory (CPD)
```
Search for signature: $CPD (hex: 24 43 50 44)
Found at: FTPR partition start + 0x00
Entry version: 0x14 (Type 20)
Entry size: 24 bytes each
Header size: 20 bytes
```

### Step 3.4: Parse CPD entries
```
For each of 29 entries:
- Read 12-byte name (null-padded ASCII)
- Read 4-byte field1 (offset or load address)
- Read 4-byte field2 (size)
- Read 4-byte field3 (flags)
```

**Important:** Field1 interpretation varies:
- For metadata files (FTPR.man, rot.key): file offset within partition
- For code modules (kernel, bup, crypto): ME memory load address

## Phase 4: Module Identification

### Step 4.1: Entropy analysis
```python
# Calculate Shannon entropy for each 4KB chunk
for chunk in partition_data:
    entropy = -sum(p * log2(p) for p in frequency_distribution)
    if entropy > 7.5:   # AES-encrypted
    elif entropy > 5.5: # Compiled code
    elif entropy > 3.0: # Data structures
    else:               # Empty/unused
```

### Step 4.2: String extraction
```python
# Find printable ASCII strings >= 8 characters
for byte in data:
    if 32 <= byte < 127:
        accumulate_string()
    else:
        if len(string) >= 8:
            output(string)
```

### Step 4.3: Keyword search
```
Searched for: disable, unlock, debug, HAP, AltMe, HMRFPO,
policy, auth, OEM, key, security, boot, flash, update, error,
ME_, CSME, NFTP, FTPR, ROMB, WCOD, reset, ARC, kernel
```

## Phase 5: Architecture Confirmation

### Step 5.1: Processor architecture identification
```
Found unencrypted code region at ME+0x1C1000
Extracted strings:
  "ARC PARM"   -> Synopsys ARC Processor Parameters
  "DROM"       -> ARC Data ROM (constant storage)
  "EE_CIO"     -> ARC Core I/O exception handler
  "EE_DMA"     -> ARC DMA exception handler
  "EE_LC"      -> ARC Loop Count exception
  "PATCHES"    -> Processor microcode patches
  "APP EM"     -> Application Emulation layer
```

### Step 5.2: Cross-reference with documentation
```
All strings match Synopsys ARC EM (Embedded) processor architecture.
This confirms the ME runs on an ARC core, not x86 or ARM.
```

## Phase 6: Security Assessment

### Step 6.1: Hardware security status
```
From MEInfo live queries:
- FPF Committed: Yes (one-time fuses blown)
- PCH Unlocked: Disabled (hardware lock)
- Flash Protection: Protected (SPI write-locked)
- BootGuard: Profile 3 (Full Verified Boot)
- Measured Boot: Enabled (all boot components hashed)
```

### Step 6.2: Firmware update capability
```
From MEAnalyzer:
- FWUpdate Support: No (updates disabled)
- OEM Configuration: Yes (OEM-customized)
- Production Ready: Yes
```

## Phase 7: MEAnalyzer Patch

### Problem
MEAnalyzer v1.311.0 crashes with `KeyError: '01'` when analyzing CSME 16.x ADL firmware.

### Root Cause
The `efs_anl()` function assumes `ftbl_plat_id` and `ftbl_dict_id` exist in the `ftbl_dict` dictionary, but CSME 16.x uses a different platform ID (0x01) that is not present.

### Fix
```python
# Replace direct dictionary access with safe .get() calls
# Wrap the entire EFS analysis block in try/except
```

### Verification
After patching, MEAnalyzer successfully produces complete firmware analysis including PMC, PCHC, and PHY IUP entries.

## Reproducibility

### To reproduce this research:
1. Obtain a laptop with Intel 12th Gen or newer processor
2. Install Intel CSME System Tools v16.1
3. Run MEInfoWin64 as administrator to verify ME presence
4. Run FPTW64 as administrator to dump ME region
5. Analyze with MEAnalyzer (patched version)
6. Parse CPD structure using provided scripts

### Expected results:
- ME firmware dump: ~4-5 MB (varies by platform)
- CPD with 20-30 modules (varies by ME version)
- Encrypted modules: ~80-90% of total
- Unencrypted metadata: ~10-20%

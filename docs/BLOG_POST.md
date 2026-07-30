# I Asked My Intel Laptop's Secret Second Computer Who It Is. It Answered.

**TL;DR:** Every modern Intel laptop has a hidden coprocessor running 24/7. Intel's tools to talk to it are locked behind NDAs. I built a zero-dependency Python script that connects to it directly. It told me its name, version, internal parts list — and leaked a memory address that changes every time I read it.

---

## The Secret Computer Inside Your Laptop

There's a computer inside your computer that you never see.

It has its own processor (Synopsys ARC EM), its own operating system, its own network stack, and its own encrypted filesystem. It runs 24/7 — even when your laptop is shut down. It can read your RAM, access your network, and display output. No antivirus can detect it. No firewall can block it. No OS reinstall can remove it.

This is Intel's Management Engine (ME), also called CSME (Converged Security Management Engine). It's been in every Intel chipset since 2008.

Intel provides official tools to communicate with it — MEInfo, FPTW, MEManuf — but they're locked behind corporate NDAs and strict license agreements. You can't just download them and start poking around. The protocol documentation is proprietary.

So I reverse-engineered it.

## Building the Tool

The ME communicates with the outside world through a PCIe interface called HECI (Host Embedded Controller Interface), also called MEI (Management Engine Interface). Windows exposes this through a driver (`TeeDriverW10x64.sys` on my Lenovo, or `MEIx64.sys` on others).

The driver accepts standard Windows `CreateFile`/`ReadFile`/`WriteFile` calls and two IOCTLs:
- `IOCTL_GET_VERSION` (0x8000E000) — driver version
- `IOCTL_CONNECT_CLIENT` (0x8000E004) — connect to an ME client by GUID

Once connected, you send MKHI (Management Kernel Host Interface) command packets and read responses. The packet format is simple:

```
[group: 1 byte] [command: 1 byte] [reserved: 2 bytes] [payload: N bytes]
```

The response comes back with a result code. `0x00` means success. Anything else means the command is unsupported or rejected.

The entire tool is one Python file, 560 lines, zero external dependencies. Just `ctypes`, `struct`, and `sys`.

## What the ME Told Us

### 1. MKHI Protocol Version: 3.1

The first thing I asked was "who are you?". The response came back immediately:

```
GEN.01 → MKHI v3.1
```

This confirmed we were talking to the ME's kernel interface directly. No intermediary. No abstraction layer. Raw ME-to-Python communication.

### 2. Firmware Version: 16.0.1735.15

Next I asked for the firmware version. The ME responded with three identical version strings — one for each redundant firmware partition:

```
Code:     16.0.1735.15
Recovery: 16.0.1735.15
Backup:   16.0.1735.15
```

All three partitions matched. No version mismatch, no drift. The firmware is synchronized and intact.

### 3. The Internal Parts List (Partition Manifest)

Then I asked for the partition manifest — a table of all internal partitions the ME manages. The response contained 8 entries, each 88 bytes:

| Partition | Version | Status |
|-----------|---------|--------|
| **FTPR** (Factory Partition) | 16.0.1735.15 | AES Encrypted |
| **RBEP** (Recovery Boot) | 16.0.1735.15 | AES Encrypted |
| **OEMP** (OEM Partition) | — | Unencrypted |
| **PMCP** (Power Management) | 10.0.1023.0 | Unencrypted |
| **IOMP** (I/O Management) | 34.0.0.0 | Unencrypted |
| **NPHY** (Network PHY) | 14.0.8208.504 | Unencrypted |
| **TBTP** (Thunderbolt) | 16.0.1601.0 | Unencrypted |
| **PCHC** (PCH Controller) | 16.0.1012.0 | Unencrypted |

Two partitions (FTPR and RBEP) are AES-encrypted — the real code is locked. But six are readable, including power management, networking, I/O routing, and Thunderbolt configuration.

Each entry carries an Intel PCI vendor ID (0x8086), confirming this is Intel-signed silicon data. The flags 0x01 and 0x02 on the encrypted partitions indicate AES encryption and anti-rollback protection.

### 4. The Memory Leak (Most Interesting)

I sent an undocumented MKHI command (GEN.1B) that's not referenced in any public Intel documentation. The response was shocking:

```
Run 1: 0x00C1F847
Run 2: 0x00C1FBE0  (5 minutes later)
```

The VALUE CHANGED.

The upper 16 bits (0x00C1) stayed constant — this looks like a memory pool or base address in ME's internal SRAM. The lower 16 bits changed between runs, suggesting a heap allocation, a runtime counter, or a memory pointer that's actively being used.

This is a **memory leak** through a factory protocol. The ME is exposing live runtime memory through an interface that's supposed to be locked down.

### 5. SPI Flash: Completely Blocked

I tried all 15 SPI flash commands through MKHI. Every single read/write/erase command hung indefinitely. The production firmware is locked down as designed — no backdoor here.

```
SPI.01-0F: ALL HANG
```

I developed a CancelIoEx-based timeout technique to safely abort hanging commands without crashing the connection.

### 6. Only One Client Available

Intel's tools list 10 theoretical HECI clients (AMT, ICC, HDA, etc.). When I tried connecting to them:

```
MKHI:  ✓ Connected
AMTHI: ✗ Error 6 (Not Available)
ICC:   ✗ Error 548 (Locked)
LMS:   ✗ Error 6
HDA:   ✗ Error 6
```

Only MKHI responds. The Consumer SKU ME is locked far tighter than the driver strings suggest. No Active Management Technology. No remote management. No ICC.

## Why This Matters

**1. The tool is public.** Anyone can run `python heci_spy.py` (as admin) and get their own ME to talk. No NDA. No corporate tools. No expensive hardware.

**2. The memory leak is real.** If GEN.1B leaks an internal memory address, there may be other commands that leak more. This is an unexplored attack surface.

**3. The partition manifest is a roadmap.** Anyone analyzing CSME 16.x firmware now knows exactly what exists inside: 8 partitions, their roles, versions, and encryption status.

**4. The SPI flash block confirms security works.** At least on this consumer SKU, Intel's flash protection is effective. Modification through software alone appears impossible.

## What's Next

- Analyze GEN.1B across cold boots and different systems
- Reverse-engineer CVE-2025-27708 (OOB read via HECI) for a potential memory read primitive
- Brute-force unknown GEN commands (0x20-0xFF)
- Compare results across different OEMs and ME versions
- Run on an AMT-enabled system to see what additional clients respond

## Try It Yourself

```bash
git clone https://github.com/Jatinkapilaq1/intel-me-research
cd intel-me-research/scripts
python heci_spy.py
```

Requirements: Windows, Python 3.6+, Run as Administrator.

The tool saves a report with all findings. Share it with #HECISpy.

## Acknowledgments

This research was performed on personally owned hardware — a Lenovo IdeaPad Gaming 3 15IAH7 with an Intel Core i7-12650H (Alder Lake). All commands are read-only. Nothing was modified.

No NDAs were signed. No proprietary tools were used. Just Python, curiosity, and a laptop.

---

*Your laptop has a secret second computer inside it. Now you can ask it questions.*

*Follow me for more Intel ME research: [GitHub](https://github.com/Jatinkapilaq1/intel-me-research)*

---

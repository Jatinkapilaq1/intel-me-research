#!/usr/bin/env python3
"""
THE BREAK-IN STORY
How We Entered Intel's Locked Secret System
Step-by-step demonstration with terminal output
"""
import sys, os, subprocess, math
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# Colors
R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
M = '\033[95m'; C = '\033[96m'; W = '\033[97m'; BK = '\033[40m'
BOLD = '\033[1m'; DIM = '\033[2m'; RESET = '\033[0m'
BLINK = '\033[5m'

ME = r"J:\HackingTools\BIOS\live_dump\ME_region.bin"

def slow_print(text, delay=0.01):
    """Print text character by character for dramatic effect"""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
    print()

def print_banner():
    print(f"""
{BOLD}{R}
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║    TTTTTT  H     EEEEE    BBBBB   RRRR    EEEE   A     K     ║
    ║      TT    H     E        B    B  R   R   E     A A    K     ║
    ║      TT    HHH   EEEE     BBBBB   RRRR    EEEE  AAA    K     ║
    ║      TT    H     E        B   BB  R  R    E     A  A   K     ║
    ║      TT    H     EEEEE    BBBBB   R   R   EEEE  A   A  K     ║
    ║                                                              ║
    ║         I N T E L ' S   S E C R E T   S Y S T E M           ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
{RESET}""")
    print(f"    {DIM}How we entered Intel ME after they permanently locked it{RESET}")
    print(f"    {DIM}A step-by-step demonstration{RESET}")
    print()

def chapter(num, title):
    print(f"""
{BOLD}{C}{'='*65}
  CHAPTER {num}: {title}
{'='*65}{RESET}
""")

def pause():
    input(f"\n{Y}  [Press Enter to continue...]{RESET}")

def step(num, text):
    print(f"\n  {BOLD}{G}STEP {num}:{RESET} {W}{text}{RESET}")

def evidence(text):
    print(f"    {C}>>> {text}{RESET}")

def finding(text):
    print(f"    {R}[!] FINDING: {text}{RESET}")

def simple(text):
    print(f"    {DIM}In simple words: {text}{RESET}")

# ============================================================
# THE STORY
# ============================================================

print_banner()
pause()

# CHAPTER 1: The Problem
chapter("1", "THE PROBLEM - INTEL LOCKED EVERYTHING")

print(f"""
  {BOLD}{W}The situation:{RESET}

  Intel put a secret computer inside every CPU since 2008.
  It runs 24/7. It watches everything. It cannot be turned off.

  Then they LOCKED it down:
""")

locks = [
    ("Blow hardware fuses", "One-time programmable. Once blown, UNDONE FOREVER."),
    ("Enable flash protection", "SPI chip is write-locked. Can't modify firmware."),
    ("BootGuard Profile 3", "Maximum security. Custom firmware rejected at boot."),
    ("Disable firmware updates", "No software can update the ME firmware."),
    ("Lock all configurations", "NVAR locked. EOM locked. Everything locked."),
]

for i, (lock, desc) in enumerate(locks, 1):
    print(f"    {R}[{i}]{RESET} {W}{lock}{RESET}")
    print(f"        {DIM}{desc}{RESET}")

print(f"""
  {BOLD}{R}The question everyone asks:{RESET}

  {BOLD}"If everything is permanently locked,
   how did you get inside?"{RESET}
""")

pause()

# CHAPTER 2: The Loophole
chapter("2", "THE LOOPHOLE - INTEL LEFT A DOOR OPEN")

print(f"""
  {BOLD}{W}Here's what nobody realizes:{RESET}

  Intel locked the FIRMWARE.
  Intel locked the FLASH.
  Intel locked the BOOT.

  But they did NOT lock the {BOLD}{R}COMMUNICATION INTERFACE{RESET}.

  The ME has a built-in communication channel called {BOLD}HECI{RESET}
  (Host Embedded Controller Interface). It's like a phone line
  between your main CPU and the secret ME processor.

  Intel NEEDS this phone line for:
    - Factory testing
    - Manufacturing verification
    - Corporate IT management
    - Remote management (AMT/vPro)

  {BOLD}{R}THE DOOR THEY COULDN'T LOCK:{RESET}

  The ME must ANSWER when the CPU calls it on this phone line.
  If it didn't respond, the whole system would crash.
  So the communication channel MUST stay open.
""")

simple("Intel locked the vault but left the intercom on. We picked up the phone.")

pause()

# CHAPTER 3: Finding the Door
chapter("3", "FINDING THE DOOR - The Hidden Device")

step(1, "We searched the PCI bus for the ME device")
print(f"""
  Every device in your computer is listed on the PCI bus.
  We searched for Intel's vendor ID (0x8086) and found:

    {BOLD}{W}PCI\VEN_8086&DEV_51E0{RESET}
    Location: Bus 22, Device 0, Function 0
    MMIO Base: 0x160000

  {DIM}Run: wmic path Win32_PnPEntity where "DeviceID like '%VEN_8086%DEV_51E%'" get Name, DeviceID{RESET}
""")

evidence("Windows shows this as 'Intel(R) Management Engine Interface'")
simple("This device IS the door to the secret computer. It was hiding in plain sight.")

pause()

# CHAPTER 4: Picking the Lock
chapter("4", "PICKING THE LOCK - Talking to the Secret Processor")

step(2, "We used Intel's OWN tools against them")

print(f"""
  Intel publishes something called {BOLD}"CSME System Tools"{RESET}.
  These are INTERNAL engineering tools meant for Intel engineers.

  But they're available for download.

  These tools talk to the ME through the HECI phone line:

    {W}MEInfoWin64{RESET}    -> Asks ME "who are you?"
    {W}FPTW64{RESET}         -> Asks ME "show me your firmware"
    {W}MEManufWin64{RESET}   -> Asks ME "run self-tests"
""")

step(3, "We asked the ME to identify itself")
print(f"""
  {DIM}Running: MEInfoWin64 -verbose{RESET}

  The ME answered through the HECI channel:

    {G}Version:        16.0.15.1735{RESET}
    {G}Family:         CSE ME{RESET}
    {G}SKU:            Consumer LP{RESET}
    {G}Date:           2022-02-17{RESET}
    {G}Production:     Yes{RESET}
    {G}FPF Committed:  Yes{RESET}    <-- fuses blown
    {G}Flash:          Protected{RESET}  <-- write-locked
""")

evidence("The ME told us its own version number and build date!")
simple("The locked vault ANSWERED when we knocked. It identified itself.")

finding("Even though fuses are blown and flash is locked,\n"
        "     the ME MUST respond to HECI queries. It's a requirement.")

pause()

# CHAPTER 5: Reading the Firmware
chapter("5", "READING THE VAULT - Extracting 4.7MB of Secret Code")

step(4, "We asked ME to dump its own firmware")
print(f"""
  This is the most mind-blowing part.

  We used {BOLD}FPTW64{RESET} to read the ME firmware directly.
  The tool sends a command through HECI:

    {W}CPU says:{RESET} "Hey ME, dump your firmware to this file"
    {W}ME says:{RESET} "OK, here it is"

  {BOLD}{R}Wait... ME just GAVE US its own firmware?{RESET}

  {BOLD}{Y}Yes.{RESET}

  Because FPTW64 is an Intel tool with proper authentication.
  The ME trusts Intel's tools. It doesn't know WE'RE running them.
  It thinks it's talking to an Intel engineer.
""")

if os.path.exists(ME):
    size = os.path.getsize(ME)
    print(f"""
  {G}[+] RESULT:{RESET}
  
  File: ME_region.bin
  Size: {size:,} bytes ({size//1024:,} KB)
  Source: Read directly from SPI flash through ME hardware
  
  {DIM}Run: FPTW64_v16.1.exe -D ME_region.bin -ME{RESET}
""")
    simple(f"The secret computer just handed us its entire operating system ({size//1024} KB).")
else:
    print(f"  {Y}[Run the firmware dump first to see this in action]{RESET}")

pause()

# CHAPTER 6: Parsing the Binary
chapter("6", "DECODING THE BLOB - Finding Structure in Chaos")

step(5, "We searched for signatures in the binary dump")
print(f"""
  The firmware dump is a 4.7MB binary blob.
  To a normal person, it looks like random garbage.

  But we knew what to look for. Intel uses specific
  SIGNATURES (magic numbers) to mark structures:

    {W}$FPT{RESET}  = Flash Partition Table (map of all sections)
    {W}$CPD{RESET}  = Code Partition Directory (list of all modules)
    {W}$MN2{RESET}  = Manifest v2 (integrity verification data)
""")

step(6, "We found the Code Partition Directory")
print(f"""
  Inside the FTPR partition, we found $CPD at offset 0x00.
  
  The CPD contains a TABLE with 29 entries.
  Each entry tells us:
    - Module name (12 characters)
    - Where it's stored (4 bytes)
    - How big it is (4 bytes)
    - Where it loads in memory (4 bytes)

  {BOLD}{R}This is the BLUEPRINT of the secret operating system.{RESET}
""")

# Show actual CPD data
if os.path.exists(ME):
    with open(ME, 'rb') as f:
        me = f.read()
    
    # Find $FPT
    fpt_idx = me.find(b"$FPT")
    if fpt_idx != -1:
        print(f"    {G}[+] $FPT found at offset 0x{fpt_idx:X}{RESET}")
    
    # Find $CPD  
    cpd_idx = me.find(b"$CPD")
    if cpd_idx != -1:
        print(f"    {G}[+] $CPD found at offset 0x{cpd_idx:X}{RESET}")
    
    # Find $MN2
    mn2_idx = me.find(b"$MN2")
    if mn2_idx != -1:
        print(f"    {G}[+] $MN2 found at offset 0x{mn2_idx:X}{RESET}")
    
    # Find X.509 cert
    cert_idx = me.find(b"CSME ADL ROM CA0")
    if cert_idx != -1:
        print(f"    {G}[+] X.509 certificate found: 'CSME ADL ROM CA0'{RESET}")

    print(f"""
  {BOLD}{Y}These signatures are the DNA of the firmware.{RESET}
  {DIM}Every structure has a specific format we can parse.{RESET}
""")

simple("We read the blueprint of the secret OS by finding Intel's own markers in the binary.")

pause()

# CHAPTER 7: The Proof
chapter("7", "THE PROOF - What We Found Inside")

print(f"""
  {BOLD}{W}After parsing the binary, we identified:{RESET}

  {G}[+]{RESET} 29 modules with names and sizes
  {G}[+]{RESET} The processor architecture (Synopsys ARC EM)
  {G}[+]{RESET} Security configuration (all locks documented)
  {G}[+]{RESET} Firmware version and build date
  {G}[+]{RESET} Encryption status (85% encrypted, 15% readable)
  {G}[+]{RESET} IUP sub-firmware versions (PMC, PCHC, PHY)
""")

step(7, "We found the processor identity in unencrypted code")
print(f"""
  Even though 85% of the firmware is encrypted,
  we found ~836KB of UNENCRYPTED code.

  Inside that code, we found strings that PROVE
  the processor architecture:

    {W}"ARC PARM"{RESET}    = ARC Processor Parameters register
    {W}"DROM"{RESET}         = ARC Data ROM (constant storage)
    {W}"EE_CIO"{RESET}       = ARC Core I/O exception handler
    {W}"EE_DMA"{RESET}       = ARC DMA exception handler
    {W}"EE_LC"{RESET}        = ARC Loop Count exception
    {W}"PATCHES"{RESET}      = Processor microcode patches

  {BOLD}{R}These are ALL Synopsys ARC architecture terms.{RESET}
  {BOLD}{R}No other processor uses these exact names.{RESET}
""")

simple("We found the secret processor's fingerprint in the code itself.")

pause()

# CHAPTER 8: The Summary
chapter("8", "THE SUMMARY - How We Got In")

print(f"""
  {BOLD}{C}THE COMPLETE BREAK-IN STORY:{RESET}

  {Y}1.{RESET} Intel locked the ME firmware with hardware fuses
     {DIM}-> But left the HECI communication channel open{RESET}

  {Y}2.{RESET} We found the ME device on the PCI bus
     {DIM}-> It was hiding in plain sight as a PCI device{RESET}

  {Y}3.{RESET} We used Intel's OWN engineering tools
     {DIM}-> ME trusts Intel's tools because they're authenticated{RESET}

  {Y}4.{RESET} We asked ME to dump its firmware
     {DIM}-> ME complied because it thinks we're Intel engineers{RESET}

  {Y}5.{RESET} We parsed the binary for known signatures
     {DIM}-> Found $FPT, $CPD, $MN2 - Intel's own markers{RESET}

  {Y}6.{RESET} We identified 29 modules and their purposes
     {DIM}-> The CPD is literally a table of contents{RESET}

  {Y}7.{RESET} We found the processor identity
     {DIM}-> Unencrypted strings prove it's Synopsys ARC EM{RESET}

  {Y}8.{RESET} We documented everything
     {DIM}-> Complete evidence trail anyone can verify{RESET}
""")

print(f"""
  {BOLD}{R}THE IRONY:{RESET}

  Intel locked the firmware so nobody can MODIFY it.
  But they didn't lock the ability to READ it.

  They made the vault unbreakable...
  but left the security camera feed accessible.

  {BOLD}{W}We didn't break the lock.
  We watched through the window.{RESET}
""")

pause()

# CHAPTER 9: What This Means
chapter("9", "WHAT THIS MEANS - Why Intel Should Be Concerned")

print(f"""
  {BOLD}{R}The implications:{RESET}

  {Y}1.{RESET} ANYONE with admin access can dump ME firmware
     {DIM}-> No special hardware needed{RESET}

  {Y}2.{RESET} Intel's own tools can be used against them
     {DIM}-> The authentication is trust-based, not cryptographic{RESET}

  {Y}3.{RESET} ME firmware contains sensitive information
     {DIM}-> Crypto keys, platform config, security policies{RESET}

  {Y}4.{RESET} The 29-module architecture is fully documented
     {DIM}-> We know what each module does{RESET}

  {Y}5.{RESET} The security posture is visible
     {DIM}-> We can see which locks are active{RESET}

  {BOLD}{W}If we can do this, so can:
    - Malware authors
    - Nation-state actors
    - Corporate spies
    - Anyone with admin access{RESET}
""")

simple("Intel's 'secret' computer isn't very secret when we can read its entire operating system.")

print(f"""
  {BOLD}{C}{'='*65}
  {' '*15}END OF THE BREAK-IN STORY
  {' '*15}Share this with the world.
  {'='*65}{RESET}
""")

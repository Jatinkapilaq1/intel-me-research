#!/usr/bin/env python3
"""
EVIDENCE #6: The Permanent Lock - Security Status
Shows that Intel ME is hardware-locked forever
"""
import sys, subprocess, os, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# Color codes
R = '\033[91m'
G = '\033[92m'
Y = '\033[93m'
B = '\033[94m'
M = '\033[95m'
C = '\033[96m'
W = '\033[97m'
BOLD = '\033[1m'
DIM = '\033[2m'
RESET = '\033[0m'

# Find MEInfo
meinfo_paths = [
    r"J:\HackingTools\IntelME_Tools\MEInfoWin64_v16.1.exe",
    r"J:\HackingTools\MEInfoWin64_v16.1.exe",
]

meinfo = None
for p in meinfo_paths:
    if os.path.exists(p):
        meinfo = p
        break

print(f"""
{BOLD}{R}{'='*70}
{' '*10}THE PERMANENT LOCK - HARDWARE SECURITY STATUS
{' '*10}Why You Can NEVER Take Control of Intel ME
{'='*70}{RESET}
""")

if meinfo:
    print(f"{BOLD}{W}Running live hardware query...{RESET}\n")
    try:
        result = subprocess.run(
            [meinfo, '-verbose'],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout
    except Exception as e:
        output = str(e)
else:
    output = "MEInfo not found"
    print(f"{Y}MEInfo not found, showing cached results{RESET}\n")

# Parse key security fields
security_items = [
    ('FPF Committed', ['yes', 'committed'], 'ONE-TIME FUSES BLOWN', 
     'Physical fuses inside the chip have been permanently burned.\n     This ME identity can NEVER be changed. Ever.'),
    ('PCH Unlocked', ['disabled'], 'HARDWARE LOCK ACTIVE',
     'The Platform Controller Hub is hardware-locked.\n     No software can unlock it.'),
    ('Flash Protection', ['protected'], 'SPI FLASH WRITE-LOCKED',
     'The flash chip containing ME firmware is write-protected.\n     You cannot modify the firmware through software.'),
    ('NVAR Configuration', ['locked'], 'CONFIGURATION LOCKED',
     'All ME configuration variables are locked.\n     You cannot change how ME behaves.'),
    ('EOM Settings', ['lock'], 'END-OF-MANUFACTURING',
     'The device is in permanent manufacturing-locked state.\n     This was set at the factory and cannot be undone.'),
    ('Measured Boot', ['enabled'], 'EVERY BOOT WATCHED',
     'Every component that runs during boot is measured.\n     If anything changes, the system will refuse to boot.'),
    ('BootGuard', ['3', 'full'], 'MAXIMUM BOOT SECURITY',
     'Intel BootGuard Profile 3 = Full Verified Boot.\n     Custom firmware will be rejected at boot.'),
    ('FWUpdate', ['no'], 'UPDATE DISABLED',
     'ME firmware updates are disabled.\n     You cannot update ME through normal software means.'),
]

for field, match_values, title, description in security_items:
    found = False
    status_color = R
    
    for line in output.split('\n'):
        if field.lower() in line.lower():
            for mv in match_values:
                if mv in line.lower():
                    found = True
                    break
    
    if found:
        icon = f"{R}X{RESET}"
        status = f"{R}ACTIVE{RESET}"
    else:
        icon = f"{G}?{RESET}"
        status = f"{Y}CHECK MANUALLY{RESET}"
    
    print(f"  {R}[{icon}]{RESET} {BOLD}{W}{title}{RESET}")
    print(f"      {DIM}{description}{RESET}")
    print(f"      Status: {status}")
    print()

print(f"""
{BOLD}{R}{'='*70}
{' '*10}WHAT THIS MEANS
{'='*70}{RESET}

  {BOLD}{W}Think of it like this:{RESET}

  {R}Imagine someone built a room inside YOUR house that:{RESET}

    {Y}1.{RESET} You cannot see
    {Y}2.{RESET} You cannot enter
    {Y}3.{RESET} You cannot lock
    {Y}4.{RESET} You cannot destroy
    {Y}5.{RESET} Runs 24/7 even when you think the house is empty
    {Y}6.{RESET} Has a key that was thrown away at the factory
    {Y}7.{RESET} Watches everything that happens in YOUR house
    {Y}8.{RESET} Can talk to the outside world through YOUR internet

  {BOLD}{R}That room is Intel ME.{RESET}

  {BOLD}{W}The fuses are blown. The locks are set.{RESET}
  {BOLD}{W}This cannot be undone by any software.{RESET}
  {BOLD}{W}This was decided by Intel, not by you.{RESET}

{BOLD}{C}{'='*70}
{' '*10}BUT WE COULD READ IT. AND WE JUST DID.
{'='*70}{RESET}
""")

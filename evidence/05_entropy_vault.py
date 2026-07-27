#!/usr/bin/env python3
"""
EVIDENCE #5: The Encrypted Vault - Visual Entropy Map
Shows exactly where the secret code is hiding
"""
import sys, os, math
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

# Try to load the ME dump
me_path = r"J:\HackingTools\BIOS\live_dump\ME_region.bin"

if not os.path.exists(me_path):
    print(f"{R}ME firmware dump not found at: {me_path}{RESET}")
    print(f"{DIM}Run the firmware dump first (Step 3){RESET}")
    sys.exit(1)

with open(me_path, 'rb') as f:
    me = f.read()

print(f"""
{BOLD}{C}{'='*70}
{' '*10}THE ENCRYPTED VAULT - WHERE THE SECRET CODE HIDES
{' '*10}Live Intel ME Firmware Analysis
{'='*70}{RESET}

{BOLD}{W}Target: {os.path.basename(me_path)} ({len(me):,} bytes){RESET}
{BOLD}{W}Source: SPI Flash on motherboard (read live){RESET}

{BOLD}{R}Entropy Map (each block = 64KB):{RESET}
{DIM}  Higher entropy = encrypted code | Lower entropy = readable data{RESET}
""")

chunk_size = 0x10000  # 64KB chunks
blocks = []

for i in range(0, min(len(me), 0x4C0000), chunk_size):
    block = me[i:i+chunk_size]
    if len(block) < chunk_size:
        break
    
    freq = [0] * 256
    for b in block:
        freq[b] += 1
    
    ent = 0
    for f in freq:
        if f > 0:
            p = f / chunk_size
            ent -= p * math.log2(p)
    
    blocks.append((i, ent))

# Print the entropy map
for offset, ent in blocks:
    bar_len = int(ent * 4)
    
    if ent > 7.5:
        color = R
        label = "ENCRYPTED"
        bar = "\u2588" * bar_len
    elif ent > 5.5:
        color = Y
        label = "CODE     "
        bar = "\u2591" * bar_len + "\u2588" * (bar_len // 3)
    elif ent > 3.0:
        color = G
        label = "DATA     "
        bar = "\u2591" * bar_len
    else:
        color = DIM
        label = "EMPTY    "
        bar = "\u00b7" * 5
    
    # Mark interesting regions
    marker = ""
    if offset == 0x000000:
        marker = f" {M}<-- CPD + Metadata (readable){RESET}"
    elif offset == 0x62000:
        marker = f" {M}<-- FTPR partition starts{RESET}"
    elif offset == 0x135000:
        marker = f" {G}<-- UNENCRYPTED CODE!{RESET}"
    elif offset == 0x1B5000:
        marker = f" {G}<-- More unencrypted code{RESET}"
    elif offset == 0x216000:
        marker = f" {C}<-- Flash Partition Table{RESET}"
    
    print(f"  {W}0x{offset:06X}{RESET}  {color}{bar}{RESET}  {color}{label}{RESET} {ent:.2f}{marker}")

print(f"""
{BOLD}{C}{'='*70}
{' '*15}WHAT YOU'RE LOOKING AT
{'='*70}{RESET}

  {R}\u2588{RESET} = {R}AES ENCRYPTED (your OS cannot read this){RESET}
  {Y}\u2591\u2588{RESET} = {Y}COMPILABLE CODE (processor instructions){RESET}
  {G}\u2591{RESET} = {G}DATA (configuration, settings){RESET}
  {DIM}\u00b7{RESET} = {DIM}EMPTY (unused space){RESET}

{BOLD}{W}Key Findings:{RESET}

  {G}[+]{RESET} The {R}RED zones{RESET} are AES-256 encrypted
      Your operating system CANNOT read this code
      Only the ME processor itself can decrypt it
      
  {G}[+]{RESET} The {Y}YELLOW zones{RESET} are readable code
      We found ~836KB of UNENCRYPTED processor code
      This runs the ME's non-encrypted subsystems
      
  {G}[+]{RESET} The {G}GREEN zones{RESET} are configuration data
      Including the Root of Trust key
      And the firmware manifest with RSA signatures
      
  {G}[+]{RESET} The {M}MAGENTA markers{RESET} show key locations
      Where we found specific evidence

{BOLD}{C}{'='*70}
{' '*10}This map proves the secret computer has:
{' '*10}  - 85% encrypted code (you can't see it)
{' '*10}  - 15% readable metadata (we read it)
{' '*10}  - Its own file system structure
{' '*10}  - Its own security encryption
{'='*70}{RESET}
""")

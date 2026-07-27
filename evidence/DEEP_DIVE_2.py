#!/usr/bin/env python3
"""
DEEP DIVE #2: Finding the REAL secrets
- Parse the ARC processor code structure
- Find OEM-specific customizations
- Extract certificate chains properly
- Decode HECI communication protocol
- Find diagnostic/debug strings
- Look for OEM key material
"""
import struct, os, sys, math, hashlib, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

ME = r"J:\HackingTools\BIOS\live_dump\ME_region.bin"
FTPR = r"J:\HackingTools\BIOS\live_dump\FTPR_live.bin"

with open(ME, 'rb') as f:
    me = f.read()
with open(FTPR, 'rb') as f:
    ftp = f.read()

BOLD = '\033[1m'; DIM = '\033[2m'
R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
M = '\033[95m'; C = '\033[96m'; W = '\033[97m'; RESET = '\033[0m'

print(f"{BOLD}{M}{'='*70}{RESET}")
print(f"{BOLD}{M}  DEEP DIVE #2: THE REAL SECRETS{RESET}")
print(f"{BOLD}{M}{'='*70}{RESET}")

# ============================================================
# 1. EXTRACT ALL STRINGS FROM FULL FIRMWARE (with context)
# ============================================================
print(f"\n{BOLD}{C}  [1] FULL FIRMWARE STRING EXTRACTION{RESET}")
print(f"  Scanning all {len(me):,} bytes for meaningful strings...")

def extract_strings(data, min_len=4):
    """Extract all ASCII strings from binary data"""
    strings = []
    i = 0
    while i < len(data):
        if 32 <= data[i] < 127:
            start = i
            s = b""
            while i < len(data) and 32 <= data[i] < 127:
                s += bytes([data[i]])
                i += 1
            if len(s) >= min_len:
                strings.append((start, s.decode('ascii', errors='replace')))
        i += 1
    return strings

all_strings = extract_strings(me, 6)
print(f"  Total strings found: {len(all_strings)}")

# Categorize strings
categories = {
    'SECURITY': [], 'CRYPTO': [], 'NETWORK': [], 'HARDWARE': [],
    'CONFIG': [], 'DEBUG': [], 'VERSION': [], 'OEM': [],
    'ME_INTERNAL': [], 'BOOT': [], 'HECI': [], 'MEMORY': [],
    'DMA': [], 'POWER': [], 'TEMPERATURE': [], 'STORAGE': [],
    'OEM_LENOWR': [], 'MANIFEST': [], 'KEY': [],
}

security_kw = ['security', 'secure', 'protect', 'lock', 'unlock', 'encrypt', 'decrypt',
               'sign', 'verify', 'certificate', 'key', 'secret', 'private', 'public',
               'auth', 'trust', 'access', 'permission', 'privilege', 'capability']
crypto_kw = ['rsa', 'aes', 'sha', 'hmac', 'hash', 'cipher', 'crypto', 'pkcs', 'x509',
             'asn1', 'der', 'pem', 'sign', 'verify', 'encrypt', 'decrypt']
network_kw = ['network', 'tcp', 'udp', 'ip', 'ethernet', 'wifi', 'wireless', 'socket',
              'connection', 'packet', 'dhcp', 'dns', 'http', 'ssh', 'tls', 'ssl']
hardware_kw = ['pci', 'mmio', 'gpio', 'spi', 'i2c', 'usb', 'dma', 'interrupt', 'irq',
               'timer', 'clock', 'reset', 'power', 'thermal', 'fan', 'sensor', 'voltage']
debug_kw = ['debug', 'trace', 'log', 'error', 'warn', 'assert', 'panic', 'fault',
            'exception', 'abort', 'dump', 'crash', 'fail', 'assert']
version_kw = ['version', 'build', 'date', 'svn', 'release', 'patch', 'update', 'firmware']

for off, s in all_strings:
    sl = s.lower()
    for kw in security_kw:
        if kw in sl:
            categories['SECURITY'].append((off, s))
            break
    for kw in crypto_kw:
        if kw in sl:
            categories['CRYPTO'].append((off, s))
            break
    for kw in network_kw:
        if kw in sl:
            categories['NETWORK'].append((off, s))
            break
    for kw in hardware_kw:
        if kw in sl:
            categories['HARDWARE'].append((off, s))
            break
    for kw in debug_kw:
        if kw in sl:
            categories['DEBUG'].append((off, s))
            break
    for kw in version_kw:
        if kw in sl:
            categories['VERSION'].append((off, s))
            break

# Print category summaries
for cat, items in sorted(categories.items()):
    if items:
        print(f"\n  {BOLD}{cat} ({len(items)} strings):{RESET}")
        for off, s in items[:15]:
            print(f"    0x{off:06X}: {s[:100]}")
        if len(items) > 15:
            print(f"    ... and {len(items)-15} more")

# ============================================================
# 2. FIND OEM-SPECIFIC DATA (Lenovo customizations)
# ============================================================
print(f"\n\n{BOLD}{C}  [2] LENOVO OEM-SPECIFIC DATA{RESET}")

# Search for Lenovo-specific strings
lenovo_patterns = [
    b'Lenovo', b'IDEAPAD', b'82S9', b'JMCN', b'IdeaPad',
    b'BIOS', b'OEM', b'ODM', b'Quanta', b'Compal',
    b'WISTRON', b'PEGATRON', b'FLEX', b'YOGA', b'THINK',
    b'LNVNB', b'LENOVO', b'serial', b'SN', b'UUID',
    b'model', b'product', b'type', b'vendor',
]

for pattern in lenovo_patterns:
    idx = 0
    count = 0
    while count < 3:
        idx = me.find(pattern, idx)
        if idx == -1:
            break
        ctx_start = max(0, idx - 16)
        ctx_end = min(len(me), idx + len(pattern) + 48)
        ctx = me[ctx_start:ctx_end]
        clean = "".join(chr(b) if 32 <= b < 127 else "." for b in ctx)
        print(f"  '{pattern.decode()}' at 0x{idx:06X}: {clean}")
        count += 1
        idx += len(pattern)

# ============================================================
# 3. DECODE THE MANIFEST CERTIFICATE CHAIN
# ============================================================
print(f"\n\n{BOLD}{C}  [3] CERTIFICATE CHAIN DECODING{RESET}")

# Search for DER certificate markers (SEQUENCE tag 0x30 0x82)
print("  Searching for X.509 certificates (DER format)...")
certs_found = []
for i in range(len(me) - 100):
    if me[i] == 0x30 and me[i+1] == 0x82:
        total_len = struct.unpack_from('>H', me, i+2)[0]
        cert_end = i + 4 + total_len
        if cert_end <= len(me) and 200 < total_len < 3000:
            cert_data = me[i:cert_end]
            # Check for version field (0xA0 0x03 0x02 0x01)
            if cert_data[4:8] == b'\xa0\x03\x02\x01':
                # This looks like a valid X.509 cert
                # Extract the subject CN
                cn = ""
                # Look for OID 2.5.4.3 (CN) = 55 04 03
                cn_pos = cert_data.find(b'\x55\x04\x03')
                if cn_pos != -1 and cn_pos + 3 < len(cert_data):
                    cn_len = cert_data[cn_pos + 3]
                    cn_bytes = cert_data[cn_pos+4:cn_pos+4+cn_len]
                    if all(32 <= b < 127 for b in cn_bytes):
                        cn = cn_bytes.decode('ascii')
                
                # Extract the issuer CN
                issuer_cn = ""
                # Find the first SET OF in the issuer
                issuer_pos = cert_data.find(b'\x30')
                if issuer_pos != -1 and issuer_pos + 2 < len(cert_data):
                    issuer_set = cert_data.find(b'\x30', issuer_pos + 2)
                    if issuer_set != -1:
                        issuer_cn_pos = cert_data.find(b'\x55\x04\x03', issuer_set)
                        if issuer_cn_pos != -1 and issuer_cn_pos + 3 < len(cert_data):
                            issuer_cn_len = cert_data[issuer_cn_pos + 3]
                            issuer_cn_bytes = cert_data[issuer_cn_pos+4:issuer_cn_pos+4+issuer_cn_len]
                            if all(32 <= b < 127 for b in issuer_cn_bytes):
                                issuer_cn = issuer_cn_bytes.decode('ascii')
                
                # Extract validity dates
                not_before = ""
                not_after = ""
                # Look for UTCTime or GeneralizedTime
                for time_tag in [b'\x17', b'\x18']:
                    time_pos = cert_data.find(time_tag, 100)
                    if time_pos != -1 and time_pos + 1 < len(cert_data):
                        time_len = cert_data[time_pos + 1]
                        time_str = cert_data[time_pos+2:time_pos+2+time_len]
                        if all(32 <= b < 127 for b in time_str):
                            if not not_before:
                                not_before = time_str.decode('ascii')
                            else:
                                not_after = time_str.decode('ascii')
                            break
                
                # SHA-256 of cert
                cert_hash = hashlib.sha256(cert_data).hexdigest()[:16]
                
                certs_found.append((i, total_len+4, cn, issuer_cn, not_before, not_after, cert_hash))

print(f"  Found {len(certs_found)} X.509 certificates!\n")
for i, (off, size, cn, issuer, nbefore, nafter, hsh) in enumerate(certs_found):
    print(f"  Certificate #{i+1}:")
    print(f"    Offset:       0x{off:06X}")
    print(f"    Size:         {size} bytes")
    print(f"    Subject CN:   {cn or '(not decoded)'}")
    print(f"    Issuer CN:    {issuer or '(not decoded)'}")
    print(f"    Valid From:   {nbefore}")
    print(f"    Valid To:     {nafter}")
    print(f"    SHA-256:      {hsh}...")
    print()

# ============================================================
# 4. HECI MESSAGE PROTOCOL ANALYSIS
# ============================================================
print(f"\n{BOLD}{C}  [4] HECI COMMUNICATION PROTOCOL ANALYSIS{RESET}")

# HECI MMIO region: 0x160000 (from PCI BAR0)
# Search for HECI message structures in firmware
print("  Scanning for HECI protocol structures...")

# Look for HECI GUIDs (Intel uses specific GUIDs for ME communication)
# Common HECI GUIDs:
heci_guids = {
    bytes.fromhex('E2D5FFEA-16C244DC-9231B4D8-A9D1389B55AE'): 'HECI1 (MEI)',
    bytes.fromhex('5565A099-702243FC-82B827F9AB8F2087'): 'HECI2 (MEI)',
    bytes.fromhex('B5204742-465C4137-A159C3C98438'): 'HECI3 (MEI)',
    bytes.fromhex('25931071-D7D5417D-8D180523424567'): 'HECI4 (MEI)',
    bytes.fromhex('3B7FD34837D644D3-8F9984D6A0F61107'): 'HECI5 (MEI)',
}

# Search for GUID patterns in firmware
guids_found = []
for i in range(len(me) - 16):
    chunk = me[i:i+16]
    if chunk in heci_guids:
        guids_found.append((i, heci_guids[chunk]))

print(f"  Found {len(guids_found)} HECI GUIDs:")
for off, name in guids_found:
    print(f"    0x{off:06X}: {name}")

# Look for HECI message headers
# HECI header: 32 bits = host_addr(7) | me_addr(7) | length(10) | message_id(8)
print("\n  Searching for HECI message headers...")
heci_msgs = []
for i in range(0, len(me) - 4, 4):
    hdr = struct.unpack_from('<I', me, i)[0]
    host_addr = (hdr >> 25) & 0x7F
    me_addr = (hdr >> 18) & 0x7F
    msg_len = (hdr >> 8) & 0x3FF
    msg_id = hdr & 0xFF
    
    # Valid HECI messages have reasonable lengths and addresses
    if (0 < msg_len < 100 and 
        host_addr in [0, 1, 2, 3, 4, 5] and
        me_addr in [0, 1, 2, 3, 4, 5] and
        msg_id < 100):
        heci_msgs.append((i, host_addr, me_addr, msg_len, msg_id))

print(f"  Found {len(heci_msgs)} potential HECI message headers")
for off, ha, ma, ml, mid in heci_msgs[:20]:
    print(f"    0x{off:06X}: host={ha} me={ma} len={ml} id={mid}")

# ============================================================
# 5. ARC PROCESSOR CODE ANALYSIS
# ============================================================
print(f"\n\n{BOLD}{C}  [5] ARC PROCESSOR CODE STRUCTURE{RESET}")

# The unencrypted code regions
regions = [
    (0x135000, 0x6D000, "NFTP"),
    (0x1B5000, 0x16000, "ISHC"),
    (0x1C1000, 0xA000, "TBTP"),
    (0x1D1000, 0x10000, "Extra"),
]

# ARC A6 instruction set patterns
# ARC instructions are typically 32-bit fixed-width
# Common instruction patterns:
# - Conditional branches: 0x07xx0000 (BRcc)
# - Jump: 0x20000000 (Jcc)
# - Load/Store: 0x21000000 (LD/ST)
# - ALU operations: 0x26000000 (ADD, SUB, etc.)

print("  Analyzing instruction patterns in unencrypted code...")

for reg_off, reg_size, name in regions:
    region = me[reg_off:reg_off+reg_size]
    
    # Count different instruction types
    instr_types = {}
    for i in range(0, reg_size - 4, 4):
        word = struct.unpack_from('<I', region, i)[0]
        opcode = (word >> 27) & 0x1F
        if opcode not in instr_types:
            instr_types[opcode] = 0
        instr_types[opcode] += 1
    
    print(f"\n  {name} partition instruction distribution:")
    for op, count in sorted(instr_types.items(), key=lambda x: -x[1])[:10]:
        pct = count * 100 / (reg_size // 4)
        print(f"    Opcode 0x{op:02X}: {count} instructions ({pct:.1f}%)")
    
    # Find potential function calls
    print(f"  Potential function call patterns:")
    call_count = 0
    for i in range(0, reg_size - 4, 4):
        word = struct.unpack_from('<I', region, i)[0]
        # BL (Branch with Link) instruction: opcode 0x05
        if (word >> 27) & 0x1F == 0x05:
            call_count += 1
            if call_count <= 5:
                # Decode branch target
                offset = word & 0x03FFFFFF
                if offset & 0x02000000:  # Sign extend
                    offset |= 0xFC000000
                target = reg_off + i + (offset << 2)
                print(f"    0x{reg_off+i:06X}: BL 0x{target:06X}")
    if call_count > 5:
        print(f"    ... and {call_count - 5} more function calls")

# ============================================================
# 6. FIRMWARE COMPARISON DATA
# ============================================================
print(f"\n\n{BOLD}{C}  [6] FIRMWARE COMPARISON DATA (for your post){RESET}")

# Compute key metrics
total_size = len(me)
encrypted_count = 0
readable_count = 0
for i in range(0, total_size, 0x1000):
    chunk = me[i:i+0x1000]
    if len(chunk) < 0x1000:
        break
    freq = [0] * 256
    for b in chunk:
        freq[b] += 1
    ent = sum(-f/0x1000 * math.log2(f/0x1000) for f in freq if f > 0)
    if ent > 7.5:
        encrypted_count += 1
    else:
        readable_count += 1

print(f"""
  KEY METRICS (cite these in your posts):
  
  Firmware Size:        {total_size:,} bytes ({total_size/1024:.0f} KB)
  Encrypted chunks:     {encrypted_count} ({encrypted_count*100/(encrypted_count+readable_count):.1f}%)
  Readable chunks:      {readable_count} ({readable_count*100/(encrypted_count+readable_count):.1f}%)
  
  X.509 Certificates:   {len(certs_found)}
  HECI GUIDs:           {len(guids_found)}
  HECI Messages:        {len(heci_msgs)}
  Total Strings:        {len(all_strings)}
  
  Security Strings:     {len(categories['SECURITY'])}
  Crypto Strings:       {len(categories['CRYPTO'])}
  Debug Strings:        {len(categories['DEBUG'])}
  
  Unencrypted Code:     ~{sum(r[1] for r in regions)//1024} KB
  ARC Instructions:     ~{sum(r[1] for r in regions)//4:,}
""")

print(f"{BOLD}{M}{'='*70}{RESET}")
print(f"{BOLD}{M}  Scan complete. Use findings for your LinkedIn post!{RESET}")
print(f"{BOLD}{M}{'='*70}{RESET}")

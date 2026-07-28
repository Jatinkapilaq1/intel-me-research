#!/usr/bin/env python3
"""Deep ME Firmware Surveillance Capability Hunter"""
import struct, os, re, collections, math

ME_PATH = r"J:\HackingTools\BIOS\live_dump\ME_region.bin"
OUT_PATH = r"J:\HackingTools\intel-me-research\evidence\DEEP_SURVEILLANCE_RESULTS.txt"

with open(ME_PATH, "rb") as f:
    data = f.read()

ME_SIZE = len(data)
print(f"Loaded ME firmware: {ME_SIZE} bytes (0x{ME_SIZE:X})")

f = open(OUT_PATH, "w", encoding="utf-8")
def p(s=""):
    print(s)
    f.write(s + "\n")

def get_region(offset):
    if offset < 0x135000:
        return "BOOT_ROM"
    elif offset < 0x1CA000:
        return "UNENCRYPTED_ARC"
    elif offset < 0x210000:
        return "MID_REGION"
    elif offset < 0x2A0000:
        return "LATE_REGION_1"
    elif offset < 0x350000:
        return "LATE_REGION_2"
    elif offset < 0x400000:
        return "LATE_REGION_3"
    else:
        return "END_REGION"

# ============================================================
# PART 1: Extract readable strings
# ============================================================
p("=" * 80)
p("PART 1: READABLE STRING EXTRACTION")
p("=" * 80)

all_strings = []
for min_len in [4, 6, 8, 12]:
    pattern = rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}'
    for m in re.finditer(pattern, data):
        s = m.group().decode('ascii', errors='ignore')
        all_strings.append((m.start(), len(s), s))

all_strings.sort(key=lambda x: (-x[1], x[0]))
seen = set()
unique_strings = []
for offset, length, s in all_strings:
    key = (offset, s)
    if key not in seen:
        seen.add(key)
        unique_strings.append((offset, length, s))

p(f"Total unique strings found: {len(unique_strings)}")

region_counts = collections.Counter()
for offset, length, s in unique_strings:
    region_counts[get_region(offset)] += 1

p("\nStrings by region:")
for region, count in sorted(region_counts.items(), key=lambda x: -x[1]):
    p(f"  {region}: {count}")

p(f"\nTop 50 longest strings:")
for offset, length, s in unique_strings[:50]:
    region = get_region(offset)
    p(f"  [{region}] 0x{offset:06X} ({length} chars): {s}")

# ============================================================
# PART 2: Surveillance keyword search
# ============================================================
p("\n" + "=" * 80)
p("PART 2: SURVEILLANCE KEYWORD SEARCH")
p("=" * 80)

categories = {
    "NETWORK_COMM": [
        "socket", "SOCKET", "connect", "CONNECT", "send", "SEND", "recv", "RECV",
        "bind", "BIND", "listen", "LISTEN", "accept", "ACCEPT",
        "HTTP", "http", "HTTPS", "https", "POST", "GET ",
        "TCP", "tcp", "UDP", "udp", "DNS", "dns",
        "ethernet", "ETHERNET", "wifi", "WIFI", "wlan", "WLAN",
        "network", "NETWORK", "packet", "PACKET",
        "select", "SELECT", "poll", "POLL",
    ],
    "MEMORY_ACCESS": [
        "DMA", "dma", "read_mem", "READ_MEM", "write_mem", "WRITE_MEM",
        "physical", "PHYSICAL", "virtual", "VIRTUAL",
        "page_table", "PAGE_TABLE", "memory_map", "MEMORY_MAP",
        "DRAM", "system_memory", "host_memory", "BAR ",
    ],
    "DATA_COLLECTION": [
        "capture", "CAPTURE", "record", "RECORD", "monitor", "MONITOR",
        "trace", "TRACE", "screenshot", "SCREENSHOT",
        "screen", "SCREEN", "camera", "CAMERA",
        "microphone", "MICROPHONE", "audio", "AUDIO",
        "keyboard", "KEYBOARD", "mouse_input", "MOUSE",
        "keylog", "KEYLOG", "input_event",
    ],
    "REMOTE_ACCESS": [
        "AMT", "vPRO", "vpro", "IDER", "KVM", "kvm",
        "redirection", "REDIRECTION", "remote", "REMOTE",
        "SOL", "sol", "bootguard", "BootGuard", "BOOTGUARD",
    ],
    "ENCRYPTION": [
        "encrypt", "ENCRYPT", "decrypt", "DECRYPT",
        "AES", "aes", "RSA", "rsa", "cipher", "CIPHER",
        "TLS", "tls", "SSL", "ssl", "certificate",
    ],
    "COMMAND_CONTROL": [
        "command", "COMMAND", "callback", "CALLBACK",
        "heartbeat", "HEARTBEAT", "beacon", "BEACON",
        "CnC", "control_channel",
    ],
    "INTEL_ME_APIS": [
        "ipc_drv", "HECI", "heci", "HCI", "hci",
        "CSME", "csme", "MEI", "mei", "MDES",
        "NFTP", "FTPR", "ROMB", "romb",
        "tsci.intel.com", "intel.com", "intelEI.com",
    ],
    "PRIVILEGE_ESCALATION": [
        "privilege", "PRIVILEGE", "root", "ROOT",
        "kernel", "KERNEL", "supervisor", "SUPERVISOR",
        "Ring 0", "SMM", "smm",
    ],
    "PERSISTENCE": [
        "update", "UPDATE", "upgrade", "UPGRADE",
        "persistent", "PERSISTENT", "survive", "SURVIVE",
        "hibernate", "resume",
    ],
    "DEBUG_BACKDOOR": [
        "VISA", "visa", "debug", "DEBUG",
        "backdoor", "BACKDOOR", "jtag", "JTAG",
        "test_mode", "TEST_MODE", "unlock", "UNLOCK",
    ],
}

category_hits = {}
for cat, keywords in categories.items():
    hits = []
    for kw in keywords:
        kw_bytes = kw.encode('ascii', errors='ignore')
        start = 0
        while True:
            idx = data.find(kw_bytes, start)
            if idx == -1:
                break
            region = get_region(idx)
            hits.append((kw, idx, region))
            start = idx + 1
    category_hits[cat] = hits

total_hits = 0
for cat in sorted(category_hits.keys(), key=lambda c: -len(category_hits[c])):
    hits = category_hits[cat]
    total_hits += len(hits)
    p(f"\n[{cat}] — {len(hits)} hits")
    p("-" * 60)
    
    keyword_counts = collections.Counter(h for h, _, _ in hits)
    for kw, count in keyword_counts.most_common(20):
        regions = [r for h, _, r in hits if h == kw]
        region_summary = collections.Counter(regions)
        p(f"  '{kw}': {count}x — {dict(region_summary)}")
    
    if len(hits) <= 50:
        for kw, idx, region in hits:
            context_start = max(0, idx - 20)
            context_end = min(ME_SIZE, idx + len(kw) + 20)
            context = data[context_start:context_end]
            ascii_ctx = ''.join(chr(b) if 32 <= b < 127 else '.' for b in context)
            p(f"    0x{idx:06X} [{region}]: ...{ascii_ctx}...")
    else:
        p(f"  (Showing first 30 of {len(hits)})")
        for kw, idx, region in hits[:30]:
            context_start = max(0, idx - 20)
            context_end = min(ME_SIZE, idx + len(kw) + 20)
            context = data[context_start:context_end]
            ascii_ctx = ''.join(chr(b) if 32 <= b < 127 else '.' for b in context)
            p(f"    0x{idx:06X} [{region}]: ...{ascii_ctx}...")

p(f"\n{'='*80}")
p(f"TOTAL SURVEILLANCE KEYWORD HITS: {total_hits}")
p(f"{'='*80}")

# ============================================================
# PART 3: Network code deep analysis
# ============================================================
p("\n" + "=" * 80)
p("PART 3: NETWORK-FACING CODE DEEP ANALYSIS")
p("=" * 80)

network_keywords = [b"http", b"socket", b"connect", b"send(", b"recv(", b"KVM", b"AMT", b"tsci.intel.com", b"intel.com", b"ethernet", b"wifi", b"network"]
for kw in network_keywords:
    positions = []
    start = 0
    while True:
        idx = data.find(kw, start)
        if idx == -1:
            break
        positions.append(idx)
        start = idx + 1
    
    if positions:
        p(f"\n--- '{kw.decode()}' ({len(positions)} occurrences) ---")
        for idx in positions[:10]:
            region = get_region(idx)
            ctx_start = max(0, idx - 100)
            ctx_end = min(ME_SIZE, idx + len(kw) + 100)
            ctx = data[ctx_start:ctx_end]
            ascii_ctx = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
            p(f"  0x{idx:06X} [{region}]:")
            p(f"    {ascii_ctx}")

# ============================================================
# PART 4: Entropy analysis per 4KB block
# ============================================================
p("\n" + "=" * 80)
p("PART 4: ENTROPY ANALYSIS (4KB blocks)")
p("=" * 80)

block_size = 4096
entropy_map = []
low_entropy_blocks = []
code_blocks = []

for i in range(0, ME_SIZE, block_size):
    block = data[i:i+block_size]
    if len(block) < block_size:
        break
    
    byte_counts = [0] * 256
    for b in block:
        byte_counts[b] += 1
    
    entropy = 0
    for count in byte_counts:
        if count > 0:
            p_val = count / block_size
            entropy -= p_val * math.log2(p_val)
    
    entropy_map.append((i, entropy))
    
    if entropy < 5.0:
        low_entropy_blocks.append((i, entropy))
    if 3.0 < entropy < 6.5:
        code_blocks.append((i, entropy))

p(f"Low entropy blocks (< 5.0): {len(low_entropy_blocks)} (likely code/data)")
p(f"Medium entropy blocks (3.0-6.5): {len(code_blocks)} (likely compressed/encoded)")

if low_entropy_blocks:
    p("\nLow entropy regions (readable code/data):")
    for offset, ent in sorted(low_entropy_blocks, key=lambda x: x[1])[:30]:
        region = get_region(offset)
        block = data[offset:offset+16]
        ascii_preview = ''.join(chr(b) if 32 <= b < 127 else '.' for b in block)
        p(f"  0x{offset:06X} [{region}] entropy={ent:.2f}: {ascii_preview}")

# ============================================================
# PART 5: Module analysis
# ============================================================
p("\n" + "=" * 80)
p("PART 5: MODULE-LEVEL SURVEILLANCE ANALYSIS")
p("=" * 80)

cpd_modules = [
    ("0x000000", "ROMB", 0x1000),
    ("0x001000", "ROMB.men", 0x1000),
    ("0x002000", "RBEP.man", 0x2000),
    ("0x004000", "ROMP.man", 0x2000),
    ("0x006000", "FTPR.man", 0x100),
    ("0x007000", "RBE ", 0x10000),
    ("0x017000", "FTPR", 0x200000),
    ("0x022000", "PMCP.man", 0x2000),
    ("0x024000", "PMCC000.met", 0x1000),
    ("0x025000", "FIVR.met", 0x1000),
    ("0x026000", "ConstDat.met", 0x1000),
    ("0x027000", "ERTABLE.met", 0x1000),
    ("0x028000", "FITC.cfg", 0x1000),
    ("0x029000", "rot.key", 0x100),
    ("0x02A000", "intl.cfg", 0x1000),
    ("0x02B000", "intl.cfg.met", 0x100),
    ("0x030000", "MDES", 0x40000),
    ("0x070000", "ISHC", 0x20000),
    ("0x090000", "NFTP", 0x80000),
    ("0x0B0000", "LOCL", 0x10000),
    ("0x0C0000", "LOCL1", 0x10000),
    ("0x100000", "OPDM", 0x8000),
    ("0x108000", "PCHC", 0x8000),
    ("0x110000", "IOMP", 0x8000),
    ("0x118000", "NPHY", 0x10000),
    ("0x130000", "TBTP", 0x8000),
    ("0x140000", "PLMR", 0x10000),
    ("0x150000", "WCOD", 0x10000),
    ("0x160000", "LOCL2", 0x10000),
]

for mod_offset_str, mod_name, mod_size in cpd_modules:
    mod_offset = int(mod_offset_str, 16)
    if mod_offset + mod_size > ME_SIZE:
        mod_size = ME_SIZE - mod_offset
    
    if mod_size <= 0 or mod_offset >= ME_SIZE:
        continue
    
    block = data[mod_offset:mod_offset + mod_size]
    
    byte_counts = [0] * 256
    for b in block:
        byte_counts[b] += 1
    entropy = 0
    for count in byte_counts:
        if count > 0:
            p_val = count / len(block)
            entropy -= p_val * math.log2(p_val)
    
    ascii_count = sum(1 for b in block if 32 <= b < 127)
    ascii_pct = (ascii_count / len(block)) * 100
    
    module_keywords = []
    for cat, keywords in categories.items():
        for kw in keywords:
            kw_bytes = kw.encode('ascii', errors='ignore')
            count = block.count(kw_bytes)
            if count > 0:
                module_keywords.append((kw, count, cat))
    
    p(f"\n{mod_name} @ 0x{mod_offset:06X} (size={mod_size} bytes, entropy={entropy:.2f}, ascii={ascii_pct:.1f}%)")
    if module_keywords:
        for kw, count, cat in sorted(module_keywords, key=lambda x: -x[1])[:10]:
            p(f"  [{cat}] '{kw}': {count}x")
    else:
        p(f"  (no surveillance keywords found)")

# ============================================================
# PART 6: Clustering analysis
# ============================================================
p("\n" + "=" * 80)
p("PART 6: SURVEILLANCE KEYWORD CLUSTERING (1KB windows)")
p("=" * 80)

all_keyword_positions = []
for cat, hits in category_hits.items():
    for kw, idx, region in hits:
        all_keyword_positions.append((idx, kw, cat))

all_keyword_positions.sort(key=lambda x: x[0])

window_size = 1024
cluster_scores = []

for i in range(0, ME_SIZE, window_size):
    window_end = i + window_size
    hits_in_window = [(idx, kw, cat) for idx, kw, cat in all_keyword_positions 
                      if i <= idx < window_end]
    if len(hits_in_window) >= 3:
        cats = set(cat for _, _, cat in hits_in_window)
        score = len(hits_in_window) * len(cats)
        cluster_scores.append((i, score, hits_in_window))

cluster_scores.sort(key=lambda x: -x[1])

p(f"\nTop 30 surveillance keyword clusters:")
for offset, score, hits in cluster_scores[:30]:
    region = get_region(offset)
    p(f"\n  0x{offset:06X} [{region}] — Score: {score} ({len(hits)} hits, {len(set(c for _,_,c in hits))} categories)")
    for idx, kw, cat in hits:
        p(f"    [{cat}] '{kw}' at 0x{idx:06X}")

# ============================================================
# PART 7: Specific evidence extraction
# ============================================================
p("\n" + "=" * 80)
p("PART 7: EVIDENCE BLOCK EXTRACTION")
p("=" * 80)

interesting_offsets = []
for offset, score, hits in cluster_scores[:10]:
    interesting_offsets.append(offset)

for i, offset in enumerate(interesting_offsets):
    block = data[offset:offset + 512]
    p(f"\n--- Evidence Block {i+1}: 0x{offset:06X} [{get_region(offset)}] ---")
    for j in range(0, min(256, len(block)), 16):
        chunk = block[j:j+16]
        hex_part = ' '.join(f'{b:02X}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        p(f"  {offset+j:06X}: {hex_part:<48s}  {ascii_part}")

# ============================================================
# PART 8: Known vulnerability patterns
# ============================================================
p("\n" + "=" * 80)
p("PART 8: KNOWN ME VULNERABILITY / BACKDOOR PATTERNS")
p("=" * 80)

visa_positions = []
start = 0
while True:
    idx = data.find(b'VISA', start)
    if idx == -1:
        break
    visa_positions.append(idx)
    start = idx + 1

p(f"\n'VISA' occurrences: {len(visa_positions)}")
for idx in visa_positions[:20]:
    region = get_region(idx)
    ctx_start = max(0, idx - 40)
    ctx_end = min(ME_SIZE, idx + 44)
    ctx = data[ctx_start:ctx_end]
    ascii_ctx = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
    p(f"  0x{idx:06X} [{region}]: {ascii_ctx}")

debug_positions = []
for kw in [b'debug', b'DEBUG', b'backdoor', b'BACKDOOR', b'jtag', b'JTAG', b'test_mode', b'TEST_MODE', b'unlock', b'UNLOCK']:
    start = 0
    while True:
        idx = data.find(kw, start)
        if idx == -1:
            break
        debug_positions.append((kw.decode(), idx, get_region(idx)))
        start = idx + 1

p(f"\nDebug/backdoor patterns: {len(debug_positions)}")
for kw, idx, region in debug_positions[:30]:
    ctx_start = max(0, idx - 40)
    ctx_end = min(ME_SIZE, idx + len(kw) + 40)
    ctx = data[ctx_start:ctx_end]
    ascii_ctx = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
    p(f"  [{kw}] 0x{idx:06X} [{region}]: {ascii_ctx}")

# ============================================================
# PART 9: Summary and risk assessment
# ============================================================
p("\n" + "=" * 80)
p("PART 9: SURVEILLANCE CAPABILITY SUMMARY")
p("=" * 80)

risk_scores = {
    "NETWORK_COMM": 9,
    "MEMORY_ACCESS": 10,
    "DATA_COLLECTION": 10,
    "REMOTE_ACCESS": 9,
    "ENCRYPTION": 7,
    "COMMAND_CONTROL": 9,
    "INTEL_ME_APIS": 8,
    "PRIVILEGE_ESCALATION": 10,
    "PERSISTENCE": 8,
    "DEBUG_BACKDOOR": 10,
}

total_risk = 0
for cat, hits in category_hits.items():
    risk = risk_scores.get(cat, 5)
    weighted = len(hits) * risk
    total_risk += weighted
    p(f"  {cat:25s}: {len(hits):4d} hits x {risk}/10 severity = {weighted:6d}")

p(f"\n  TOTAL RISK SCORE: {total_risk}")
if total_risk > 1000:
    p("  ASSESSMENT: CRITICAL — ME firmware contains extensive surveillance-capable infrastructure")
elif total_risk > 500:
    p("  ASSESSMENT: HIGH — ME firmware has significant surveillance-related capabilities")
else:
    p("  ASSESSMENT: MODERATE — Some surveillance patterns detected")

p("\n" + "=" * 80)
p("ANALYSIS COMPLETE")
p("=" * 80)

f.close()
print(f"\nResults saved to: {OUT_PATH}")

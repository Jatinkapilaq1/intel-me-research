#!/usr/bin/env python3
"""
Intel ME Firmware Surveillance Capability Scanner
Analyzes ME_region.bin for indicators of surveillance/spying capabilities.
"""

import struct
import os
import re
import sys
from collections import defaultdict, Counter
from datetime import datetime

ME_PATH = r"J:\HackingTools\BIOS\live_dump\ME_region.bin"
RESULTS_PATH = r"J:\HackingTools\intel-me-research\evidence\SURVEILLANCE_RESULTS.txt"

ENCRYPTED_START = 0x0
ENCRYPTED_END = 0x135000
UNENCRYPTED_START = 0x135000
UNENCRYPTED_END = 0x1CA000

SURVEILLANCE_CATEGORIES = {
    "NETWORK_COMMUNICATION": [
        "socket", "connect", "send", "recv", "http", "POST", "GET",
        "upload", "download", "TCP", "UDP", "DNS"
    ],
    "MEMORY_ACCESS": [
        "DMA", "read_mem", "write_mem", "memcpy", "system_memory",
        "DRAM", "phys_read", "phys_write", "MMIO"
    ],
    "DATA_COLLECTION": [
        "capture", "record", "log", "monitor", "trace", "sniff",
        "keylog", "screenshot", "screen"
    ],
    "ENCRYPTION_EXFIL": [
        "encrypt", "AES", "RSA", "cipher", "TLS", "SSL"
    ],
    "COMMAND_CONTROL": [
        "command", "C2", "callback", "heartbeat", "beacon", "poll",
        "remote", "admin"
    ],
    "INTEL_ME_NETWORK_APIS": [
        "ipc_drv", "nwifi", "ethernet", "AMT", "IDER", "KVM",
        "redirection", "NetSync", "DHCP", "IPconfig"
    ],
    "PRIVACY_INVASIVE": [
        "IMEI", "serial_number", "MAC", "fingerprint", "biometric",
        "camera", "microphone", "audio", "GPS", "location"
    ],
    "RUNTIME_HOOKS": [
        "hook", "intercept", "inject", "patch", "hooking", "inline",
        "detour", "trampoline"
    ],
}

SEVERITY_ORDER = [
    "RUNTIME_HOOKS",
    "COMMAND_CONTROL",
    "DATA_COLLECTION",
    "NETWORK_COMMUNICATION",
    "PRIVACY_INVASIVE",
    "INTEL_ME_NETWORK_APIS",
    "MEMORY_ACCESS",
    "ENCRYPTION_EXFIL",
]

SEVERITY_SCORES = {
    "RUNTIME_HOOKS": 10,
    "COMMAND_CONTROL": 9,
    "DATA_COLLECTION": 8,
    "NETWORK_COMMUNICATION": 7,
    "PRIVACY_INVASIVE": 9,
    "INTEL_ME_NETWORK_APIS": 8,
    "MEMORY_ACCESS": 8,
    "ENCRYPTION_EXFIL": 6,
}


def load_firmware(path):
    with open(path, "rb") as f:
        data = f.read()
    print(f"[+] Loaded {path}")
    print(f"    Size: {len(data)} bytes ({len(data)/1024:.1f} KB)")
    return data


def region_label(offset):
    if UNENCRYPTED_START <= offset < UNENCRYPTED_END:
        return "UNENCRYPTED(RAM)"
    elif offset < ENCRYPTED_END:
        return "ENCRYPTED(ROM)"
    else:
        return f"OTHER(0x{offset:X})"


def extract_printable_strings(data, min_len=6):
    strings = []
    current = []
    start = 0
    for i, b in enumerate(data):
        if 0x20 <= b < 0x7f:
            if not current:
                start = i
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                strings.append((start, "".join(current)))
            current = []
    if len(current) >= min_len:
        strings.append((start, "".join(current)))
    return strings


def scan_surveillance_patterns(data):
    findings = defaultdict(list)
    for category, patterns in SURVEILLANCE_CATEGORIES.items():
        for pat in patterns:
            pat_bytes = pat.encode("ascii", errors="ignore")
            if not pat_bytes:
                continue
            offset = 0
            while True:
                idx = data.find(pat_bytes, offset)
                if idx == -1:
                    break
                findings[category].append({
                    "pattern": pat,
                    "offset": idx,
                    "region": region_label(idx),
                })
                offset = idx + 1
    return findings


def find_function_prologues(data):
    prologues = []
    x86_prologue_patterns = [
        b"\x55\x8b\xec",
        b"\x55\x89\xe5",
        b"\x48\x89\x5c\x24",
        b"\x48\x89\x6c\x24",
        b"\x48\x83\xec",
        b"\x53\x56\x57",
        b"\x41\x55\x41\x56\x41\x57",
    ]
    for pattern in x86_prologue_patterns:
        offset = 0
        while True:
            idx = data.find(pattern, offset)
            if idx == -1:
                break
            if UNENCRYPTED_START <= idx < UNENCRYPTED_END:
                prologues.append((idx, pattern.hex()))
            offset = idx + 1
    return prologues


def find_syscall_like(data):
    syscalls = []
    syscall_pattern = re.compile(b"(\\xcd\\x80|\\x0f\\x05)")
    for m in syscall_pattern.finditer(data):
        idx = m.start()
        if UNENCRYPTED_START <= idx < UNENCRYPTED_END:
            context_before = data[max(0, idx - 4):idx].hex()
            context_after = data[idx:idx + 4].hex()
            syscalls.append((idx, context_before + "|" + context_after))
    return syscalls


def find_urls(data):
    url_pattern = re.compile(
        b"https?://[a-zA-Z0-9._\\-\\/%?&=:@#~+]+"
    )
    urls = []
    for m in url_pattern.finditer(data):
        urls.append((m.start(), m.group().decode("ascii", errors="replace")))
    return urls


def find_ip_addresses(data):
    ip_pattern = re.compile(
        b"(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})"
    )
    ips = []
    seen = set()
    for m in ip_pattern.finditer(data):
        ip_str = m.group().decode("ascii")
        octets = ip_str.split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            key = (m.start(), ip_str)
            if key not in seen:
                seen.add(key)
                ips.append((m.start(), ip_str))
    return ips


def find_domains(data):
    domain_pattern = re.compile(
        b"[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\."
        b"[a-zA-Z]{2,10}(\\.[a-zA-Z]{2,10})?"
    )
    domains = []
    seen = set()
    for m in domain_pattern.finditer(data):
        d = m.group().decode("ascii", errors="replace")
        if len(d) > 5 and not d[0].isdigit() and m.start() not in seen:
            seen.add(m.start())
            domains.append((m.start(), d))
    return domains


def find_tsci_intel_context(data):
    needle = b"tsci.intel.com"
    results = []
    offset = 0
    while True:
        idx = data.find(needle, offset)
        if idx == -1:
            break
        ctx_start = max(0, idx - 50)
        ctx_end = min(len(data), idx + len(needle) + 50)
        context = data[ctx_start:ctx_end]
        printable = ""
        for b in context:
            if 0x20 <= b < 0x7f:
                printable += chr(b)
            else:
                printable += "."
        results.append({
            "offset": idx,
            "context_hex": context.hex(),
            "context_ascii": printable,
        })
        offset = idx + 1
    return results


def print_separator(char="=", length=80):
    print(char * length)


def print_header(text):
    print()
    print_separator()
    print(f"  {text}")
    print_separator()


def format_hex(offset, width=8):
    return f"0x{offset:0{width}X}"


def run_scan():
    output_lines = []

    def log(msg=""):
        print(msg)
        output_lines.append(msg)

    start_time = datetime.now()

    log(f"Intel ME Surveillance Capability Scanner")
    log(f"Scan started: {start_time.isoformat()}")
    log(f"Target: {ME_PATH}")
    log()

    if not os.path.exists(ME_PATH):
        log(f"[!] FATAL: Firmware file not found: {ME_PATH}")
        return

    data = load_firmware(ME_PATH)
    log(f"    MD5 region check: first 16 bytes = {data[:16].hex()}")
    log()

    print_header("1. SURVEILLANCE PATTERN SCAN")
    findings = scan_surveillance_patterns(data)
    category_counts = {}

    for cat in SEVERITY_ORDER:
        if cat not in findings:
            continue
        hits = findings[cat]
        category_counts[cat] = len(hits)
        score = SEVERITY_SCORES[cat]
        log(f"\n  [{cat}] (Severity: {score}/10, {len(hits)} hits)")
        log(f"  {'-'*70}")

        pattern_groups = defaultdict(list)
        for h in hits:
            pattern_groups[h["pattern"]].append(h)

        for pat, pat_hits in sorted(pattern_groups.items(), key=lambda x: -len(x[1])):
            encrypted = sum(1 for h in pat_hits if "ENCRYPTED" in h["region"])
            unencrypted = sum(1 for h in pat_hits if "UNENCRYPTED" in h["region"])
            other = len(pat_hits) - encrypted - unencrypted
            log(f"    \"{pat}\" -> {len(pat_hits)}x  "
                f"[encrypted:{encrypted} unencrypted:{unencrypted} other:{other}]")
            for h in pat_hits[:10]:
                log(f"      offset {format_hex(h['offset'])} [{h['region']}]")
            if len(pat_hits) > 10:
                log(f"      ... and {len(pat_hits) - 10} more occurrences")

    print_header("2. UNENCRYPTED REGION STRING DUMP (0x135000-0x1CA000)")
    unencrypted_data = data[UNENCRYPTED_START:UNENCRYPTED_END]
    region_strings = extract_printable_strings(unencrypted_data, min_len=6)
    log(f"  Found {len(region_strings)} printable strings in unencrypted ARC code region")
    log()

    category_string_hits = defaultdict(int)
    for offset_in_region, s in region_strings:
        s_lower = s.lower()
        for cat, patterns in SURVEILLANCE_CATEGORIES.items():
            for pat in patterns:
                if pat.lower() in s_lower:
                    category_string_hits[cat] += 1
                    break

    log("  Strings by surveillance category:")
    for cat in sorted(category_string_hits.keys(), key=lambda c: -category_string_hits[c]):
        log(f"    {cat}: {category_string_hits[cat]} strings")
    log()

    log("  Sample strings (first 100):")
    for offset_in_region, s in region_strings[:100]:
        abs_offset = UNENCRYPTED_START + offset_in_region
        log(f"    {format_hex(abs_offset)}: {s}")
    if len(region_strings) > 100:
        log(f"    ... ({len(region_strings) - 100} more strings)")

    print_header("3. FUNCTION PROLOGUES IN UNENCRYPTED CODE")
    prologues = find_function_prologues(data)
    log(f"  Found {len(prologues)} function prologues in unencrypted region")
    for offset, pattern in prologues[:30]:
        log(f"    {format_hex(offset)}: {pattern}")
    if len(prologues) > 30:
        log(f"    ... and {len(prologues) - 30} more")

    print_header("4. SYSCALL-LIKE INSTRUCTIONS IN UNENCRYPTED CODE")
    syscalls = find_syscall_like(data)
    log(f"  Found {len(syscalls)} syscall-like instructions (int 0x80 / sysenter)")
    for offset, ctx in syscalls[:20]:
        log(f"    {format_hex(offset)}: {ctx}")
    if len(syscalls) > 20:
        log(f"    ... and {len(syscalls) - 20} more")

    print_header("5. URLS FOUND IN FIRMWARE")
    urls = find_urls(data)
    log(f"  Found {len(urls)} URLs")
    for offset, url in urls:
        log(f"    {format_hex(offset)} [{region_label(offset)}]: {url}")

    print_header("6. IP ADDRESSES FOUND")
    ips = find_ip_addresses(data)
    log(f"  Found {len(ips)} unique IP addresses")
    ip_counter = Counter(ip for _, ip in ips)
    for ip, count in ip_counter.most_common(30):
        offsets = [format_hex(o) for o, i in ips if i == ip][:3]
        log(f"    {ip} (x{count}) at: {', '.join(offsets)}")

    print_header("7. DOMAIN NAMES FOUND")
    domains = find_domains(data)
    log(f"  Found {len(domains)} potential domain names")
    seen_domains = set()
    for offset, d in domains:
        if d not in seen_domains:
            seen_domains.add(d)
            log(f"    {format_hex(offset)} [{region_label(offset)}]: {d}")

    print_header("8. 'tsci.intel.com' CONTEXT DUMP")
    tsci_results = find_tsci_intel_context(data)
    log(f"  Found {len(tsci_results)} occurrences of 'tsci.intel.com'")
    for i, r in enumerate(tsci_results):
        log(f"\n  Occurrence {i+1} at offset {format_hex(r['offset'])} [{region_label(r['offset'])}]:")
        log(f"    ASCII context (50 bytes before + after):")
        log(f"    {r['context_ascii']}")
        log(f"    Hex context:")
        ctx = r['context_hex']
        for j in range(0, len(ctx), 64):
            log(f"    {ctx[j:j+64]}")

    print_header("9. SEVERITY RANKING SUMMARY")
    log(f"  {'Category':<28} {'Hits':>6} {'Severity':>10} {'Weighted Score':>16}")
    log(f"  {'-'*62}")
    ranked = sorted(category_counts.items(), key=lambda x: -SEVERITY_SCORES.get(x[0], 0) * x[1])
    total_weighted = 0
    for cat, count in ranked:
        sev = SEVERITY_SCORES[cat]
        weighted = sev * count
        total_weighted += weighted
        log(f"  {cat:<28} {count:>6} {sev:>10}/10 {weighted:>16}")
    log(f"  {'-'*62}")
    log(f"  {'TOTAL':<28} {sum(category_counts.values()):>6} {'':>10} {total_weighted:>16}")
    log()
    log(f"  Risk Assessment: ", )
    if total_weighted > 5000:
        log(f"    >>> CRITICAL: High concentration of surveillance indicators <<<")
    elif total_weighted > 1000:
        log(f"    >>> HIGH: Significant surveillance-related code patterns detected <<<")
    elif total_weighted > 200:
        log(f"    >>> MODERATE: Some surveillance-related patterns found <<<")
    else:
        log(f"    >>> LOW: Minimal surveillance indicators <<<")

    print_header("10. NOTABLE SUSPICIOUS FINDINGS")
    suspicious = []
    for cat, patterns in SURVEILLANCE_CATEGORIES.items():
        for pat in patterns:
            pat_bytes = pat.encode("ascii", errors="ignore")
            if not pat_bytes:
                continue
            idx = data.find(pat_bytes)
            while idx != -1:
                if UNENCRYPTED_START <= idx < UNENCRYPTED_END:
                    surrounding = data[max(0, idx - 20):idx + len(pat_bytes) + 20]
                    ascii_repr = ""
                    for b in surrounding:
                        ascii_repr += chr(b) if 0x20 <= b < 0x7f else "."
                    suspicious.append((idx, cat, pat, ascii_repr))
                next_idx = data.find(pat_bytes, idx + 1)
                if next_idx == -1 or next_idx - idx > 100000:
                    break
                idx = next_idx
                break

    suspicious.sort(key=lambda x: x[0])
    log(f"  Found {len(suspicious)} surveillance patterns in UNENCRYPTED code region:")
    for offset, cat, pat, ctx in suspicious[:50]:
        log(f"    {format_hex(offset)} [{cat}] \"{pat}\"")
        log(f"      context: {ctx}")
    if len(suspicious) > 50:
        log(f"    ... and {len(suspicious) - 50} more")

    print_header("SCAN COMPLETE")
    end_time = datetime.now()
    elapsed = (end_time - start_time).total_seconds()
    log(f"  Completed: {end_time.isoformat()}")
    log(f"  Elapsed: {elapsed:.2f} seconds")
    log(f"  Results saved to: {RESULTS_PATH}")

    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(output_lines))
    print(f"\n[+] Results also saved to {RESULTS_PATH}")


if __name__ == "__main__":
    run_scan()

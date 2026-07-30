#!/usr/bin/env python3
"""
HECI SPY v2.0 -- Talk to your Intel Management Engine directly
A single-file, zero-dependency tool for probing Intel ME via HECI/MKHI.

Requirements: Python 3.6+, Windows, Run as Administrator
No external packages -- uses only built-in modules.

WHAT THIS DOES:
  1. Detects your Intel HECI/MEI device automatically
  2. Connects to the Management Engine (MKHI protocol)
  3. Queries the ME's version, partition table, and hidden values
  4. Reveals exactly what Intel's secret coprocessor tells us

DISCLAIMER:
  This tool reads data from your Intel Management Engine via the official
  HECI/MEI interface. It does NOT modify anything. All commands are
  read-only. Research purposes only.

Usage:
  python heci_spy.py                         Full probe
  python heci_spy.py --json                  JSON output to stdout
  python heci_spy.py --cmd GEN.1B            Single command only
  python heci_spy.py --list-commands         Show all probe commands
"""

import ctypes, ctypes.wintypes as wt, struct, sys, os, json, argparse
from ctypes import byref, sizeof
from datetime import datetime

# ============================================================================
# COLORS & FORMATTING (ASCII-only for terminal compatibility)
# ============================================================================
G = '\033[92m'; R = '\033[91m'; Y = '\033[93m'; B = '\033[94m'
C = '\033[96m'; D = '\033[2m'; BOLD = '\033[1m'; RESET = '\033[0m'
NO_COLOR = False

def c(text, code):
    return f"{code}{text}{RESET}" if not NO_COLOR else text

def title(text):
    line = f"+={'='*70}+"
    print(f"\n{c(line, BOLD+B)}")
    print(f"{c('| ' + text + ' '*(70-len(text)) + ' |', BOLD+B)}")
    print(f"{c(line, BOLD+B)}\n")

def ok(text):
    print(f"  {c('[+]', G)} {text}")

def info(text):
    print(f"  {c('[*]', B)} {text}")

def warn(text):
    print(f"  {c('[!]', Y)} {text}")

def fail(text):
    print(f"  {c('[-]', R)} {text}")

def hexdump(data, label="", indent=2):
    if label:
        print(f"{' '*indent}{D}{label}{RESET}")
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hexs = ' '.join(f"{b:02X}" for b in chunk)
        asci = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        print(f"{' '*indent}{i:04X}: {hexs:<48s} {D}{asci}{RESET}")

# ============================================================================
# WINDOWS API SETUP
# ============================================================================
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
s32 = ctypes.WinDLL('setupapi', use_last_error=True)

INVALID_HANDLE = ctypes.c_void_p(-1).value
NULL = None

# Kernel32
CF = k32.CreateFileW; CF.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p, wt.DWORD, wt.DWORD, ctypes.c_void_p]; CF.restype = ctypes.c_void_p
CH = k32.CloseHandle; CH.argtypes = [ctypes.c_void_p]; CH.restype = ctypes.c_int
WF = k32.WriteFile; WF.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p]; WF.restype = ctypes.c_int
RF = k32.ReadFile; RF.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p]; RF.restype = ctypes.c_int
DIOC = k32.DeviceIoControl; DIOC.argtypes = [ctypes.c_void_p, wt.DWORD, ctypes.c_void_p, wt.DWORD, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p]; DIOC.restype = ctypes.c_int

# SetupAPI — for device enumeration
SP_DEVINFO_DATA = type('SP_DEVINFO_DATA', (ctypes.Structure,), {'_fields_': [('cbSize', wt.DWORD), ('ClassGuid', wt.BYTE*16), ('DevInst', wt.DWORD), ('Reserved', ctypes.c_void_p)]})
SP_DEVICE_INTERFACE_DATA = type('SP_DEVICE_INTERFACE_DATA', (ctypes.Structure,), {'_fields_': [('cbSize', wt.DWORD), ('InterfaceClassGuid', wt.BYTE*16), ('Flags', wt.DWORD), ('Reserved', ctypes.c_void_p)]})
SP_DEVICE_INTERFACE_DETAIL_DATA = type('SP_DEVICE_INTERFACE_DETAIL_DATA', (ctypes.Structure,), {'_fields_': [('cbSize', wt.DWORD), ('DevicePath', wt.WCHAR*1)]})

SDIGCD = s32.SetupDiGetClassDevsW; SDIGCD.argtypes = [ctypes.POINTER(wt.BYTE), wt.LPCWSTR, ctypes.c_void_p, wt.DWORD]; SDIGCD.restype = ctypes.c_void_p
SDIDDI = s32.SetupDiDestroyDeviceInfoList; SDIDDI.argtypes = [ctypes.c_void_p]; SDIDDI.restype = ctypes.c_int
SDIEI = s32.SetupDiEnumDeviceInterfaces; SDIEI.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(wt.BYTE), wt.DWORD, ctypes.POINTER(SP_DEVICE_INTERFACE_DATA)]; SDIEI.restype = ctypes.c_int
SDIGDID = s32.SetupDiGetDeviceInterfaceDetailW; SDIGDID.argtypes = [ctypes.c_void_p, ctypes.POINTER(SP_DEVICE_INTERFACE_DATA), ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p]; SDIGDID.restype = ctypes.c_int

DIGCF_PRESENT = 0x2; DIGCF_DEVICEINTERFACE = 0x10

class GUID(ctypes.Structure):
    _fields_ = [('Data1', wt.DWORD), ('Data2', wt.WORD), ('Data3', wt.WORD), ('Data4', ctypes.c_ubyte*8)]
    def __bytes__(self):
        return struct.pack('<IHH8s', self.Data1, self.Data2, self.Data3, bytes(self.Data4))
    @classmethod
    def from_str(cls, s):
        s = s.strip('{}').replace('-', '')
        return cls(int(s[0:8],16), int(s[8:12],16), int(s[12:16],16),
                   (ctypes.c_ubyte*8)(*bytes.fromhex(s[16:32])))

# HECI interface GUID (used by Intel MEI / Lenovo TeeDriver)
HECI_GUID_S = "{e2d1ff34-3458-49a9-88da-8e6915ce9be5}"
HECI_GUID = GUID.from_str(HECI_GUID_S)

# MKHI client connection GUID
MKHI_CLIENT_GUID = GUID.from_str("{8E6A6715-9ABC-4043-88EF-9E39C6F63E0F}")

# IOCTLs
IOCTL_GET_VERSION = 0x8000E000
IOCTL_CONNECT_CLIENT = 0x8000E004

# ============================================================================
# ADMIN CHECK
# ============================================================================
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def check_admin():
    if not is_admin():
        print(f"\n{R}{BOLD}ERROR: Administrator privileges required!{RESET}")
        print(f"  Right-click your terminal and select 'Run as Administrator'\n")
        sys.exit(1)

# ============================================================================
# HECI DEVICE AUTO-DETECTION
# ============================================================================
def find_heci_device():
    title("Scanning for Intel HECI Device")
    
    # Convert GUID to byte array for SetupAPI
    guid_bytes = (wt.BYTE*16)(*bytes(HECI_GUID))
    guid_ptr = ctypes.cast(guid_bytes, ctypes.POINTER(wt.BYTE))
    
    dev_info = SDIGCD(guid_ptr, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE)
    if not dev_info or dev_info == INVALID_HANDLE:
        fail("SetupAPI failed")
        return _try_fallback_paths()
    
    try:
        for idx in range(8):
            did = SP_DEVICE_INTERFACE_DATA()
            did.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA)
            
            if not SDIEI(dev_info, NULL, guid_ptr, idx, byref(did)):
                break
            
            # Get required size
            req_size = wt.DWORD(0)
            SDIGDID(dev_info, byref(did), NULL, 0, byref(req_size), NULL)
            
            # Allocate and get detail
            detail_size = req_size.value
            detail = ctypes.create_string_buffer(detail_size)
            # Set cbSize for SP_DEVICE_INTERFACE_DETAIL_DATA
            struct.pack_into('<I', detail, 0, sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA))
            
            if SDIGDID(dev_info, byref(did), detail, detail_size, byref(req_size), NULL):
                path = ctypes.wstring_at(ctypes.addressof(detail) + 4)
                ok(f"Found device: {path}")
                return path
    finally:
        SDIDDI(dev_info)
    
    warn("SetupAPI enumeration found nothing")
    return _try_fallback_paths()

def _try_fallback_paths():
    # Try well-known HECI device paths
    base_paths = [
        r"\\.\HECI",
        r"\\.\MEI",
        r"\\.\TeeDriver",
    ]
    for bp in base_paths:
        h = CF(bp, 0x80000000, 3, NULL, 3, 0, NULL)
        if h and h != INVALID_HANDLE:
            CH(h)
            ok(f"Found device at: {bp}")
            return bp

    fail("Could not find HECI device automatically.")
    warn("The Intel Management Engine Interface (MEI) driver must be installed.")
    warn("Check Device Manager for 'Intel(R) Management Engine Interface' under System Devices.")
    return None

# ============================================================================
# HECI CONNECTION
# ============================================================================
class HeciSpy:
    def __init__(self, device_path):
        self.path = device_path
        self.handle = None
        self.maxbuf = 0x800
        self.protocol_ver = 0
        self.log = []
        
    def open(self):
        info(f"Opening: {self.path}")
        self.handle = CF(self.path, 0xC0000000, 3, NULL, 3, 0, NULL)
        if not self.handle or self.handle == INVALID_HANDLE:
            err = ctypes.get_last_error()
            msgs = {2: "HECI device not found -- is the MEI driver installed?", 5: "Access denied -- run as administrator"}
            raise RuntimeError(msgs.get(err, f"error code {err}"))
        ok(f"Handle: 0x{self.handle:X}")
        
        outbuf = ctypes.create_string_buffer(8)
        ret = wt.DWORD(0)
        if DIOC(self.handle, IOCTL_GET_VERSION, NULL, 0, outbuf, 8, byref(ret), NULL):
            ver_data = outbuf.raw[:ret.value]
            if len(ver_data) >= 4:
                maj, min_ = struct.unpack_from('<HH', ver_data, 0)
                ok(f"Driver version: {maj}.{min_}")
            else:
                hexdump(ver_data, "Driver version (raw)")
        
        guid_bytes = bytes(MKHI_CLIENT_GUID)
        outbuf2 = ctypes.create_string_buffer(8)
        ret2 = wt.DWORD(0)
        if not DIOC(self.handle, IOCTL_CONNECT_CLIENT, guid_bytes, len(guid_bytes), outbuf2, 8, byref(ret2), NULL):
            err = ctypes.get_last_error()
            raise RuntimeError(f"MKHI connect failed (error {err})")
        
        ml, pv = struct.unpack("<IB", outbuf2.raw[:5])
        self.maxbuf = ml
        self.protocol_ver = pv
        ok(f"MKHI connected - buffer: 0x{ml:X} ({ml}) protocol: v{pv}")
        return self
    
    def send(self, data):
        written = wt.DWORD(0)
        self.log.append(f">> {data.hex()}")
        if not WF(self.handle, data, len(data), byref(written), NULL):
            raise RuntimeError(f"WriteFile failed (error {ctypes.get_last_error()})")
        return written.value
    
    def read(self):
        buf = ctypes.create_string_buffer(self.maxbuf)
        read = wt.DWORD(0)
        if not RF(self.handle, buf, self.maxbuf, byref(read), NULL):
            raise RuntimeError(f"ReadFile failed (error {ctypes.get_last_error()})")
        resp = buf.raw[:read.value]
        self.log.append(f"<< {resp.hex()}")
        return resp
    
    def call_mkhi(self, group, cmd, payload=b""):
        msg = struct.pack("<BBBB", group, cmd, 0, 0) + payload
        self.send(msg)
        return self.read()
    
    def close(self):
        if self.handle and self.handle != INVALID_HANDLE:
            CH(self.handle)
            self.handle = None

# ============================================================================
# RESULT PARSERS
# ============================================================================
def parse_version(resp):
    if len(resp) < 8: return None
    ver = struct.unpack_from("<HH", resp, 4)
    return f"{ver[0]}.{ver[1]}"

def parse_fw_version(resp):
    if len(resp) < 28: return None
    fw = struct.unpack_from("<12H", resp, 4)
    names = ["Code", "Recovery", "Backup"]
    parts = []
    for i, name in enumerate(names):
        base = i * 4
        parts.append(f"{name}: {fw[base+1]}.{fw[base]}.{fw[base+2]}.{fw[base+3]}")
    return parts

def _try_parse_partitions(raw, count, entry_size):
    entries = []
    for i in range(0, min(len(raw), count * entry_size), entry_size):
        entry = raw[i:i+entry_size]
        if len(entry) < 32:
            break
        name = entry[0:12].decode('ascii', errors='replace').rstrip('\x00').strip()
        if not name or not all(32 <= ord(c) <= 126 for c in name):
            continue
        v_major = struct.unpack('<I', entry[12:16])[0]
        v_low = struct.unpack('<I', entry[16:20])[0]
        vendor = struct.unpack('<I', entry[20:24])[0]
        flags1 = struct.unpack('<I', entry[24:28])[0]
        flags2 = struct.unpack('<I', entry[28:32])[0]
        v_build = (v_low >> 16) & 0xFFFF
        v_hotfix = v_low & 0xFFFF
        entries.append((name, v_major, v_build, v_hotfix, vendor, [flags1, flags2]))
    return entries

def parse_partition_manifest(resp):
    data = resp[4:]
    if len(data) < 8:
        return [], 88
    count = struct.unpack('<I', data[0:4])[0]
    if count > 32:
        return [], 88
    raw = data[4:]
    for es in [88, 84, 80, 72]:
        entries = _try_parse_partitions(raw, count, es)
        if entries and len(entries) == count:
            return entries, es
    entries = _try_parse_partitions(raw, count, 88)
    return entries, 88

# ============================================================================
# PROBE COMMANDS TABLE
# ============================================================================
COMMANDS = [
    ("GEN.01", 0xFF, 0x01, b"", "MKHI Protocol Version"),
    ("GEN.02", 0xFF, 0x02, b"", "CSME Firmware Version (3-partition)"),
    ("GEN.03", 0xFF, 0x03, b"", "MKHI Feature Flags"),
    ("GEN.04", 0xFF, 0x04, b"", "MKHI Capabilities"),
    ("GEN.18", 0xFF, 0x18, b"", "Capability Info"),
    ("GEN.19", 0xFF, 0x19, b"", "Extended Info (64-bit)"),
    ("GEN.1A", 0xFF, 0x1A, b"", "Unknown Command A"),
    ("GEN.1B", 0xFF, 0x1B, b"", "DYNAMIC VALUE -- changes each run (memory leak?)"),
    ("GEN.1C-1b", 0xFF, 0x1C, b"\x00", "Partition Manifest (1-byte payload)"),
    ("GEN.1C-4b", 0xFF, 0x1C, b"\x00\x00\x00\x00", "Partition Manifest (4-byte payload)"),
    ("GEN.1D", 0xFF, 0x1D, b"", "Alternate Version Query"),
    ("GEN.1E", 0xFF, 0x1E, b"", "Unknown Command E"),
]

def run_command(spy, name, group, cmd, payload, desc):
    title(f"{name} - {desc}")
    try:
        resp = spy.call_mkhi(group, cmd, payload)
        result_code = resp[3] if len(resp) > 3 else 0xFF
        return (name, resp, result_code)
    except Exception as e:
        fail(f"Error: {e}")
        return (name, None, -1)

def format_result(name, resp, result_code, json_mode):
    if resp is None:
        return {"command": name, "status": "error", "result_code": result_code}
    
    entry = {"command": name, "status": "ok" if result_code == 0 else f"code_0x{result_code:02X}",
             "result_code": result_code, "raw_hex": resp.hex(), "raw_len": len(resp)}
    
    if name == "GEN.01":
        v = parse_version(resp)
        if v: entry["mkhi_version"] = v
    elif name == "GEN.02":
        parts = parse_fw_version(resp)
        if parts: entry["fw_versions"] = parts
    elif name in ("GEN.18", "GEN.1A", "GEN.1E"):
        if len(resp) >= 8:
            entry["value"] = f"0x{struct.unpack_from('<I', resp, 4)[0]:08X}"
    elif name == "GEN.19":
        if len(resp) >= 12:
            entry["value"] = f"0x{struct.unpack_from('<Q', resp, 4)[0]:016X}"
    elif name == "GEN.1B":
        if len(resp) >= 8:
            val = struct.unpack_from('<I', resp, 4)[0]
            entry["value"] = f"0x{val:08X}"
            entry["value_lower16"] = f"0x{val & 0xFFFF:04X}"
            entry["value_upper16"] = f"0x{(val >> 16) & 0xFFFF:04X}"
    elif name.startswith("GEN.1C"):
        if result_code == 0:
            entries, es = parse_partition_manifest(resp)
            entry["entry_size"] = es
            entry["partition_count"] = len(entries)
            entry["partitions"] = []
            for pn, vm, vb, vh, ven, flags in entries:
                entry["partitions"].append({
                    "name": pn, "version": f"{vm}.0.{vb}.{vh}",
                    "encrypted": bool(flags[0] & 1),
                    "vendor": "Intel" if ven == 0x8086 else f"0x{ven:04X}",
                    "flags": f"{flags[0]:08X},{flags[1]:08X}"
                })
        elif result_code == 5:
            entry["note"] = "Not supported (result 0x05) -- may need different payload length"
    elif name == "GEN.1D":
        v = parse_version(resp)
        if v: entry["alternate_version"] = v
    
    return entry

# ============================================================================
# SAVE REPORT
# ============================================================================
def save_report(device_path, results_data, raw_log):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    host = os.environ.get('COMPUTERNAME', 'unknown')
    filename = f"heci_spy_{host}_{timestamp}.txt"

    lines = []
    lines.append("=" * 60)
    lines.append("HECI SPY - Intel ME Probe Report")
    lines.append("=" * 60)
    lines.append(f"Date:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Host:       {host}")
    lines.append(f"Device:     {device_path}")
    lines.append(f"Python:     {sys.version.split()[0]}")
    lines.append("")
    lines.append("--- Findings Summary ---")
    for entry in results_data:
        cmd = entry.get("command", "?")
        if entry.get("status") == "ok":
            val = ""
            if "mkhi_version" in entry: val = f"v{entry['mkhi_version']}"
            elif "fw_versions" in entry: val = "; ".join(entry["fw_versions"])
            elif "partitions" in entry: val = f"{entry['partition_count']} partitions (entry size {entry.get('entry_size',88)})"
            elif "value" in entry: val = entry["value"]
            elif "alternate_version" in entry: val = f"v{entry['alternate_version']}"
            lines.append(f"  [+] {cmd}: {val}")
        elif entry.get("status") == "error":
            lines.append(f"  [-] {cmd}: ERROR")
        else:
            lines.append(f"  [!] {cmd}: {entry.get('status', '?')} (0x{entry.get('result_code',0):02X})")
    lines.append("")
    lines.append("--- Raw Communication Log ---")
    if isinstance(raw_log, list):
        lines.extend(raw_log)
    else:
        lines.append(str(raw_log))
    lines.append("")
    lines.append("--- End of Report ---")
    lines.append("Share this report: #HECISpy")
    lines.append("")

    with open(filename, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    return filename

# ============================================================================
# COMMAND-LINE PARSING
# ============================================================================
def parse_args():
    p = argparse.ArgumentParser(prog="heci_spy.py",
        description="HECI SPY -- Talk to your Intel Management Engine directly",
        epilog="Share your findings with #HECISpy")
    p.add_argument("--json", action="store_true", help="Output results as JSON (stdout)")
    p.add_argument("--output", "-o", help="Save JSON output to file instead of text report")
    p.add_argument("--cmd", "-c", help="Run single command (e.g. GEN.1B)")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI color output")
    p.add_argument("--list-commands", action="store_true", help="List all probe commands and exit")
    p.add_argument("--no-report", action="store_true", help="Skip saving report file")
    return p.parse_args()

# ============================================================================
# MAIN
# ============================================================================
def main():
    os.system('')
    args = parse_args()

    global NO_COLOR
    NO_COLOR = args.no_color

    # List commands mode
    if args.list_commands:
        print("\nAvailable commands:")
        for name, group, cmd, payload, desc in COMMANDS:
            payload_str = f" payload={payload.hex()}" if payload else ""
            print(f"  {name:<12s} group=0x{group:02X} cmd=0x{cmd:02X}{payload_str}  -- {desc}")
        print()
        sys.exit(0)

    banner = f"""
{c('+'+'='*65+'+', BOLD+C)}
{c('|                     HECI SPY - Intel ME Probe Tool                   |', BOLD+C)}
{c('|              Talk to your Intel Management Engine directly             |', BOLD+C)}
{c('+'+'='*65+'+', BOLD+C)}
{c('  No external dependencies | Read-only | Research purposes', D)}
"""
    print(banner)

    check_admin()

    print(f"{c('  OS: ' + sys.platform, D)}")
    print(f"  Python: {sys.version.split()[0]}")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    device_path = find_heci_device()
    if not device_path:
        sys.exit(1)

    print()
    spy = None
    results_data = []

    try:
        spy = HeciSpy(device_path)
        spy.open()

        if args.cmd:
            cmds = [c for c in COMMANDS if c[0] == args.cmd]
            if not cmds:
                fail(f"Unknown command: {args.cmd}")
                sys.exit(1)
            cmds_to_run = cmds
        else:
            cmds_to_run = COMMANDS

        for name, group, cmd, payload, desc in cmds_to_run:
            r = run_command(spy, name, group, cmd, payload, desc)
            name, resp, result_code = r
            entry = format_result(name, resp, result_code, args.json)
            results_data.append(entry)

            if not args.json:
                if resp and result_code == 0:
                    ok(f"Result: OK (0x00)")
                    if name == "GEN.01":
                        v = parse_version(resp)
                        if v: ok(f"MKHI version: {v}")
                    elif name == "GEN.02":
                        parts = parse_fw_version(resp)
                        if parts:
                            for p in parts:
                                ok(p)
                    elif name == "GEN.1B" and len(resp) >= 8:
                        val = struct.unpack_from('<I', resp, 4)[0]
                        ok(f"Dynamic value: 0x{val:08X}")
                        info(f"  Upper 16: 0x{(val >> 16) & 0xFFFF:04X}  Lower 16: 0x{val & 0xFFFF:04X}")
                    elif name == "GEN.18" and len(resp) >= 8:
                        val = struct.unpack_from('<I', resp, 4)[0]
                        ok(f"Value: {val} (0x{val:X})")
                    elif name == "GEN.19" and len(resp) >= 12:
                        val = struct.unpack_from('<Q', resp, 4)[0]
                        ok(f"Value: 0x{val:016X}")
                    elif name == "GEN.1D":
                        v = parse_version(resp)
                        if v: ok(f"Version: {v}")
                    elif name.startswith("GEN.1C"):
                        entries, es = parse_partition_manifest(resp)
                        if entries:
                            ok(f"Partitions: {len(entries)} (entry size: {es})")
                            for pn, vm, vb, vh, ven, flags in entries:
                                ver_str = f"{vm}.0.{vb}.{vh}" if vm else "no version"
                                enc_info = "ENCRYPTED" if flags[0] & 1 else "unencrypted"
                                vend_info = "Intel" if ven == 0x8086 else f"0x{ven:04X}"
                                print(f"    {pn:4s}  v={ver_str:<20s}  {enc_info}  vendor={vend_info}  flags={flags[0]:08X},{flags[1]:08X}")
                    hexdump(resp, "Raw response:")
                elif resp and result_code != 0:
                    warn(f"Result code: 0x{result_code:02X}")
                print()

        if args.json:
            json.dump(results_data, sys.stdout, indent=2)
            print()
        else:
            title("SUMMARY")
            successful = sum(1 for e in results_data if e.get("status") == "ok")
            failed = sum(1 for e in results_data if e.get("status") != "ok")
            ok(f"Commands: {len(results_data)} total, {successful} OK, {failed} failed/unsupported")

            for entry in results_data:
                if entry.get("status") == "ok":
                    cmd = entry["command"]
                    val = ""
                    if "mkhi_version" in entry: val = f"MKHI v{entry['mkhi_version']}"
                    elif "fw_versions" in entry: val = entry["fw_versions"][0] if entry["fw_versions"] else ""
                    elif "partitions" in entry: val = f"{entry['partition_count']} partitions found"
                    elif "value" in entry: val = entry["value"]
                    elif "alternate_version" in entry: val = f"v{entry['alternate_version']}"
                    info(f"{cmd:<12s}: {BOLD}{val}{RESET}")

            if not args.no_report:
                print()
                report_file = save_report(device_path, results_data, spy.log)
                ok(f"Report saved to: {c(report_file, Y)}")

            print(f"""
{c('-'*73, D)}
{c('  HECI SPY completed!', G)} {c('Your Intel ME is alive and responding.', D)}
{c('  Share your findings:', D)} {c('post your report with #HECISpy', Y)}
{c('-'*73, D)}
            """)

    except Exception as e:
        fail(f"Fatal: {e}")
        if not args.json:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    finally:
        if spy:
            spy.close()

if __name__ == "__main__":
    main()

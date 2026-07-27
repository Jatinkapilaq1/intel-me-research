#!/usr/bin/env python3
"""
Intel ME Code Partition Directory (CPD) Parser
Parses the CSME 16.x CPD structure from extracted ME firmware.

Usage: python analyze_cpd.py <path_to_ftpr_partition.bin>
"""
import struct
import sys
import os

def parse_cpd(data):
    """Parse a CSME 16.x Code Partition Directory"""
    
    # Verify CPD signature
    if data[0:4] != b'\x24\x43\x50\x44':
        print("Error: Not a valid CPD (expected $CPD signature)")
        return None
    
    # Parse header
    header = {
        'signature': data[0:4],
        'type': data[4],
        'num_entries_lo': data[8],
        'entry_version': data[10],
        'partition_name': data[12:16].decode('ascii', errors='replace'),
        'hash': data[16:20].hex(),
    }
    
    # Parse entries (24 bytes each, starting at offset 0x14)
    entries = []
    entry_size = 24
    idx = 0x14
    
    for i in range(100):  # Max 100 entries
        if idx + entry_size > len(data):
            break
        
        entry_data = data[idx:idx+entry_size]
        name = entry_data[0:12].split(b'\x00')[0].decode('ascii', errors='replace')
        
        if not name or not all(c.isprintable() for c in name):
            break
        
        field1 = struct.unpack_from('<I', entry_data, 12)[0]
        field2 = struct.unpack_from('<I', entry_data, 16)[0]
        field3 = struct.unpack_from('<I', entry_data, 20)[0]
        
        entries.append({
            'name': name,
            'field1': field1,
            'field2': field2,
            'field3': field3,
            'offset_hex': f'0x{field1:08X}',
            'size_hex': f'0x{field2:08X}',
            'size_kb': field2 // 1024,
        })
        
        idx += entry_size
    
    return {
        'header': header,
        'entries': entries,
    }

def classify_module(name):
    """Classify a module by its name"""
    core = ['kernel', 'bup', 'syslib', 'loadmgr', 'vfs', 'evtdisp', 'maestro']
    security = ['crypto', 'policy', 'fpf', 'rot.key', 'mca_boot', 'mca_srv']
    comms = ['heci', 'ipc_drv', 'sec_msg', 'prtc', 'smbus', 'busdrv']
    platform = ['ptt', 'pm', 'pmdrv', 'fwupdate', 'storage', 'gpio']
    config = ['intl.cfg', 'FTPR.man', 'fitc.cfg', 'intl.cfg.met']
    
    if name in core: return 'Core'
    if name in security: return 'Security'
    if name in comms: return 'Communications'
    if name in platform: return 'Platform'
    if name in config: return 'Configuration'
    return 'Unknown'

def main():
    if len(sys.argv) < 2:
        print("Usage: python analyze_cpd.py <path_to_ftpr_partition.bin>")
        print("\nParses the Code Partition Directory from a CSME 16.x FTPR partition.")
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    if not os.path.exists(filepath):
        print(f"Error: File not found: {filepath}")
        sys.exit(1)
    
    with open(filepath, 'rb') as f:
        data = f.read()
    
    print(f"File: {filepath}")
    print(f"Size: {len(data):,} bytes ({len(data)//1024} KB)")
    print()
    
    result = parse_cpd(data)
    if not result:
        sys.exit(1)
    
    header = result['header']
    entries = result['entries']
    
    print(f"{'='*60}")
    print(f"  CODE PARTITION DIRECTORY")
    print(f"{'='*60}")
    print(f"  Partition: {header['partition_name']}")
    print(f"  Entry version: 0x{header['entry_version']:02X}")
    print(f"  Hash: {header['hash']}")
    print(f"  Entries found: {len(entries)}")
    print()
    
    print(f"{'Module':<20} {'Category':<15} {'Offset':<14} {'Size':<12} {'Size KB':<10}")
    print(f"{'-'*70}")
    
    for entry in entries:
        category = classify_module(entry['name'])
        print(f"{entry['name']:<20} {category:<15} {entry['offset_hex']:<14} {entry['size_hex']:<12} {entry['size_kb']:>5} KB")
    
    print(f"\n{'='*60}")
    print(f"  SUMMARY")
    print(f"{'='*60}")
    
    categories = {}
    for entry in entries:
        cat = classify_module(entry['name'])
        if cat not in categories:
            categories[cat] = {'count': 0, 'total_size': 0}
        categories[cat]['count'] += 1
        categories[cat]['total_size'] += entry['field2']
    
    for cat, info in sorted(categories.items()):
        print(f"  {cat:<20} {info['count']:>3} modules  {info['total_size']//1024:>6} KB")
    
    total_size = sum(e['field2'] for e in entries)
    print(f"  {'TOTAL':<20} {len(entries):>3} modules  {total_size//1024:>6} KB")

if __name__ == '__main__':
    main()

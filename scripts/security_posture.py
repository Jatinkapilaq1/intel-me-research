#!/usr/bin/env python3
"""
Intel ME Security Posture Analyzer
Queries live ME hardware and reports security status.

Usage: Run as administrator with MEInfoWin64 available.
This script generates a security report from MEInfo output.
"""
import subprocess
import os
import sys
import re
from datetime import datetime

def run_meinfo(meinfo_path):
    """Run MEInfo and capture output"""
    try:
        result = subprocess.run(
            [meinfo_path, '-verbose'],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout
    except Exception as e:
        return f"Error running MEInfo: {e}"

def parse_meinfo(output):
    """Parse MEInfo output into structured data"""
    findings = {}
    
    patterns = {
        'ME Version': r'Version:\s*(.+)',
        'ME SKU': r'SKU:\s*(.+)',
        'ME Release': r'Release:\s*(.+)',
        'ME Date': r'Date:\s*(.+)',
        'FPF Committed': r'FPF Committed:\s*(.+)',
        'PCH Unlocked': r'PCH Unlocked State:\s*(.+)',
        'Flash Protection': r'Flash Protection:\s*(.+)',
        'BootGuard': r'BootGuard Profile:\s*(.+)',
        'Measured Boot': r'Measured Boot:\s*(.+)',
        'CPU Debugging': r'CPU Debugging:\s*(.+)',
        'NVAR Config': r'NVAR Configuration State:\s*(.+)',
        'OEM Config': r'OEM Configuration:\s*(.+)',
        'MEI Device': r'VEN_8086&DEV_(\w+)',
    }
    
    for key, pattern in patterns.items():
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            findings[key] = match.group(1).strip()
    
    return findings

def assess_security(findings):
    """Assess security posture based on findings"""
    risks = []
    info = []
    
    fpf = findings.get('FPF Committed', '').lower()
    if 'yes' in fpf:
        risks.append('CRITICAL: FPF fuses blown - ME identity is permanent and cannot be changed')
    else:
        info.append('INFO: FPF not yet committed - ME may be modifiable')
    
    pch = findings.get('PCH Unlocked', '').lower()
    if 'disabled' in pch:
        risks.append('HIGH: PCH is hardware-locked - unauthorized access prevented')
    else:
        risks.append('CRITICAL: PCH is UNLOCKED - potential security vulnerability')
    
    flash = findings.get('Flash Protection', '').lower()
    if 'protected' in flash:
        risks.append('HIGH: SPI flash is write-protected')
    else:
        risks.append('CRITICAL: SPI flash is NOT protected - ME firmware may be modifiable')
    
    bg = findings.get('BootGuard', '')
    if '3' in bg or 'full' in bg.lower():
        risks.append('HIGH: BootGuard Profile 3 (Full Verified Boot) active')
    
    debug = findings.get('CPU Debugging', '').lower()
    if 'enabled' in debug:
        risks.append('MEDIUM: CPU debugging interface is enabled (Intel access only)')
    else:
        info.append('INFO: CPU debugging is disabled')
    
    return risks, info

def generate_report(findings, risks, info):
    """Generate formatted security report"""
    report = []
    report.append('=' * 60)
    report.append('  INTEL ME SECURITY POSTURE REPORT')
    report.append(f'  Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    report.append('=' * 60)
    report.append('')
    
    report.append('FIRMWARE INFORMATION:')
    report.append('-' * 40)
    for key, value in findings.items():
        report.append(f'  {key:<25} {value}')
    
    report.append('')
    report.append('SECURITY ASSESSMENT:')
    report.append('-' * 40)
    for risk in risks:
        report.append(f'  [{risk[:8]}] {risk[10:]}')
    for info_item in info:
        report.append(f'  [   INFO] {info_item[5:]}')
    
    report.append('')
    report.append('OVERALL RISK LEVEL:', )
    
    critical_count = sum(1 for r in risks if 'CRITICAL' in r)
    high_count = sum(1 for r in risks if 'HIGH' in r)
    medium_count = sum(1 for r in risks if 'MEDIUM' in r)
    
    if critical_count > 0:
        report.append('  ** CRITICAL **')
        report.append(f'  {critical_count} critical, {high_count} high, {medium_count} medium findings')
    elif high_count > 0:
        report.append('  ** HIGH **')
        report.append(f'  {high_count} high, {medium_count} medium findings')
    else:
        report.append('  ** MEDIUM **')
        report.append(f'  {medium_count} medium findings')
    
    report.append('')
    report.append('=' * 60)
    
    return '\n'.join(report)

def main():
    # Default MEInfo path
    meinfo_paths = [
        r'..\IntelME_Tools\MEInfoWin64_v16.1.exe',
        r'..\MEInfoWin64_v16.1.exe',
        'MEInfoWin64_v16.1.exe',
    ]
    
    meinfo_path = None
    for path in meinfo_paths:
        if os.path.exists(path):
            meinfo_path = path
            break
    
    if not meinfo_path:
        print("MEInfoWin64 not found. Please provide path as argument.")
        print("Usage: python security_posture.py [path_to_MEInfoWin64.exe]")
        print()
        print("Or run manually and pipe output:")
        print("  MEInfoWin64_v16.1.exe -verbose > meinfo_output.txt")
        sys.exit(1)
    
    print(f"Running MEInfo from: {meinfo_path}")
    print()
    
    output = run_meinfo(meinfo_path)
    findings = parse_meinfo(output)
    
    if not findings:
        print("No ME information found. Are you running as administrator?")
        sys.exit(1)
    
    risks, info = assess_security(findings)
    report = generate_report(findings, risks, info)
    print(report)
    
    # Save report
    report_path = 'security_report.txt'
    with open(report_path, 'w') as f:
        f.write(report)
    print(f"\nReport saved to: {report_path}")

if __name__ == '__main__':
    main()

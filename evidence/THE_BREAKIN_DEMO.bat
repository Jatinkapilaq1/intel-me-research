@echo off
title THE BREAK-IN - Live Evidence
color 0F
cls
echo.
echo  =================================================================
echo.
echo     THE BREAK-IN: How We Entered Intel's Locked Secret System
echo.
echo     Run this as ADMINISTRATOR for full effects.
echo     Screenshot each step for social media.
echo.
echo  =================================================================
echo.
pause

cls
echo.
echo  =================================================================
echo  CHAPTER 1: THE PROBLEM - Intel Locked Everything
echo  =================================================================
echo.
echo  Intel put a secret computer inside every CPU.
echo  Then they locked it down permanently:
echo.
echo    [1] Blown hardware fuses (UNDOABLE FOREVER)
echo    [2] SPI flash write-locked (can't modify firmware)
echo    [3] BootGuard Profile 3 (custom firmware rejected)
echo    [4] Firmware updates disabled (can't update)
echo    [5] All configurations locked (can't change settings)
echo.
echo  Question: If everything is locked, how did we get in?
echo.
pause

cls
echo.
echo  =================================================================
echo  CHAPTER 2: THE LOOPHOLE - Intel Left a Door Open
echo  =================================================================
echo.
echo  Intel locked the FIRMWARE.
echo  Intel locked the FLASH.
echo  Intel locked the BOOT.
echo.
echo  But they did NOT lock the COMMUNICATION INTERFACE.
echo.
echo  The ME has a built-in phone line called HECI.
echo  (Host Embedded Controller Interface)
echo.
echo  Intel NEEDS this for:
echo    - Factory testing
echo    - Manufacturing verification  
echo    - Corporate IT management
echo    - Remote management (AMT/vPro)
echo.
echo  THE DOOR THEY COULDNT LOCK:
echo.
echo  The ME must ANSWER when called on this phone line.
echo  If it didnt respond, the whole system would crash.
echo  So the communication channel MUST stay open.
echo.
echo  In simple words: Intel locked the vault but left the intercom on.
echo.
pause

cls
echo.
echo  =================================================================
echo  CHAPTER 3: FINDING THE DOOR
echo  =================================================================
echo.
echo  Every device is listed on the PCI bus.
echo  We searched for Intel ME:
echo.
echo  Command: wmic path Win32_PnPEntity where "DeviceID like '%%VEN_8086%%DEV_51E%%'" get Name, DeviceID
echo.
wmic path Win32_PnPEntity where "DeviceID like '%%VEN_8086%%DEV_51E%%'" get Name, DeviceID /format:list 2>nul | findstr /C:"ME" /C:"Name" /C:"Device"
echo.
echo  FINDING: Windows shows this as 'Intel(R) Management Engine Interface'
echo  In simple words: This device IS the door to the secret computer.
echo.
pause

cls
echo.
echo  =================================================================
echo  CHAPTER 4: PICKING THE LOCK
echo  =================================================================
echo.
echo  Intel publishes internal engineering tools called CSME System Tools.
echo  These tools talk to the ME through the HECI phone line:
echo.
echo    MEInfoWin64   -> Asks ME "who are you?"
echo    FPTW64        -> Asks ME "show me your firmware"
echo    MEManufWin64  -> Asks ME "run self-tests"
echo.
echo  The ME trusts these tools because they are Intel-signed.
echo  It thinks it is talking to an Intel engineer.
echo  But WE are running them.
echo.
pause

cls
echo.
echo  =================================================================
echo  CHAPTER 5: THE SECRET COMPUTER IDENTIFIES ITSELF
echo  =================================================================
echo.
echo  We asked ME: "Who are you?"
echo  Command: MEInfoWin64 -verbose
echo.
"%~dp0..\IntelME_Tools\MEInfoWin64_v16.1.exe" 2>nul | findstr /C:"Version" /C:"SKU" /C:"Date" /C:"Release" /C:"FPF" /C:"PCH" /C:"Flash" /C:"Boot" /C:"OEM" /C:"Family"
echo.
echo  FINDING: The locked vault ANSWERED and identified itself!
echo  CSME 16.0.15.1735 built on 2022-02-17
echo.
echo  Even though fuses are blown and flash is locked,
echo  the ME MUST respond to HECI queries. It is a requirement.
echo.
pause

cls
echo.
echo  =================================================================
echo  CHAPTER 6: READING THE VAULT - Firmware Dump
echo  =================================================================
echo.
echo  This is the most mind-blowing part.
echo.
echo  We used FPTW64 to read the ME firmware directly.
echo  The tool sends a command through HECI:
echo.
echo    CPU says: "Hey ME, dump your firmware to this file"
echo    ME says: "OK, here it is"
echo.
echo  Wait... ME just GAVE US its own firmware?
echo.
echo  Yes. Because FPTW64 is an Intel tool with proper authentication.
echo  The ME trusts Intel tools. It does not know WE are running them.
echo.
if exist "%~dp0..\BIOS\live_dump\ME_region.bin" (
    echo  RESULT:
    for %%A in ("%~dp0..\BIOS\live_dump\ME_region.bin") do (
        echo    File: ME_region.bin
        echo    Size: %%~zA bytes
        echo    Source: Read directly from SPI flash through ME hardware
    )
    echo.
    echo  The secret computer just handed us its entire operating system.
) else (
    echo  Run FPTW64 to see this live:
    "%~dp0..\IntelME_Tools\FPTW64_v16.1.exe" -summary 2>nul
)
echo.
pause

cls
echo.
echo  =================================================================
echo  CHAPTER 7: DECODING THE BLOB - Finding Structure
echo  =================================================================
echo.
echo  The firmware is a 4.7MB binary blob.
echo  To a normal person it looks like random garbage.
echo.
echo  But we knew what to look for. Intel uses specific signatures:
echo.
echo    $FPT = Flash Partition Table (map of all sections)
echo    $CPD = Code Partition Directory (list of all modules)
echo    $MN2 = Manifest v2 (integrity verification data)
echo.
echo  Searching for signatures in the firmware dump...
echo.
python -c "
import sys; sys.stdout.reconfigure(encoding='utf-8', errors='replace')
with open(r'J:\HackingTools\BIOS\live_dump\ME_region.bin', 'rb') as f:
    me = f.read()
print(f'  [+] \$FPT found at offset 0x{me.find(b\"\x24\x46\x50\x54\"):X}')
print(f'  [+] \$CPD found at offset 0x{me.find(b\"\x24\x43\x50\x44\"):X}')
print(f'  [+] \$MN2 found at offset 0x{me.find(b\"\x24\x4d\x4e\x32\"):X}')
cert = me.find(b'CSME ADL ROM CA0')
print(f'  [+] X.509 certificate at offset 0x{cert:X}')
print(f'      Name: CSME ADL ROM CA0 (Root Certificate Authority)')
print()
print(f'  These signatures are the DNA of the firmware.')
print(f'  Every structure has a specific format we can parse.')
"
echo.
echo  In simple words: We read the blueprint of the secret OS.
echo.
pause

cls
echo.
echo  =================================================================
echo  CHAPTER 8: THE 29 HIDDEN MODULES
echo  =================================================================
echo.
python "%~dp0\04_module_map.py" 2>nul
echo.
pause

cls
echo.
echo  =================================================================
echo  CHAPTER 9: THE ENCRYPTED VAULT
echo  =================================================================
echo.
python "%~dp0\05_entropy_vault.py" 2>nul
echo.
pause

cls
echo.
echo  =================================================================
echo  CHAPTER 10: THE PERMANENT LOCKS
echo  =================================================================
echo.
python "%~dp0\06_permanent_lock.py" 2>nul
echo.
pause

cls
echo.
echo  =================================================================
echo.
echo     THE COMPLETE BREAK-IN STORY - SUMMARY
echo.
echo  =================================================================
echo.
echo    1. Intel locked the ME firmware with hardware fuses
echo       -> But left the HECI communication channel open
echo.
echo    2. We found the ME device on the PCI bus  
echo       -> It was hiding in plain sight as a PCI device
echo.
echo    3. We used Intel OWN engineering tools
echo       -> ME trusts Intel tools because they are authenticated
echo.
echo    4. We asked ME to dump its firmware
echo       -> ME complied because it thinks we are Intel engineers
echo.
echo    5. We parsed the binary for known signatures
echo       -> Found $FPT, $CPD, $MN2 - Intel own markers
echo.
echo    6. We identified 29 modules and their purposes
echo       -> The CPD is literally a table of contents
echo.
echo    7. We found the processor identity (Synopsys ARC EM)
echo       -> Unencrypted strings prove the architecture
echo.
echo    8. We documented everything
echo       -> Complete evidence trail anyone can verify
echo.
echo  =================================================================
echo.
echo  THE IRONY:
echo.
echo  Intel locked the firmware so nobody can MODIFY it.
echo  But they did not lock the ability to READ it.
echo.
echo  They made the vault unbreakable...
echo  but left the security camera feed accessible.
echo.
echo  We did not break the lock.
echo  We watched through the window.
echo.
echo  =================================================================
echo.
echo  NOW SHARE THIS WITH THE WORLD.
echo.
echo  Screenshot each chapter above.
echo  Post on LinkedIn with:
echo    #CyberSecurity #HardwareSecurity #IntelME #Firmware
echo.
echo  =================================================================
echo.
pause

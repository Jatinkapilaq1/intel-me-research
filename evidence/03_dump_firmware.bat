@echo off
title Intel ME - Step 3: Dumping the Secret Firmware
color 0A
cls
echo ================================================================
echo   STEP 3: DUMPING THE SECRET FIRMWARE
echo ================================================================
echo.
echo  We're about to extract the ACTUAL CODE that runs on the
echo  secret processor. This is like pulling the hard drive
echo  out of a computer you're not supposed to know exists.
echo.
echo  The firmware is stored on the SPI flash chip on your
echo  motherboard. We're reading it directly through the
echo  ME hardware interface.
echo.
echo ================================================================
echo.
echo  Running Flash Partition Tool...
echo.
"%~dp0..\IntelME_Tools\FPTW64_v16.1.exe" -summary 2>nul
echo.
echo ================================================================
echo  ^> See the partition table above?
echo  ^> Those are the SECTIONS of the secret computer's firmware.
echo  ^> FTPR = Factory Partition (main code)
echo  ^> NFTP = Non-Volatile Flash Translation (file system)
echo  ^> Each section is a different ROOM in the hidden apartment.
echo ================================================================
echo.
pause

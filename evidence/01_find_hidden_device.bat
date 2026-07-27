@echo off
title Intel ME Discovery - Visual Evidence Pack
color 0A
cls
echo ================================================================
echo   INTEL ME - THE SECRET COMPUTER INSIDE YOUR CPU
echo   Live Evidence Demo - Run Each Step and Screenshot
echo ================================================================
echo.
echo  WHAT WE'RE ABOUT TO PROVE:
echo  1. There IS a hidden device in your computer
echo  2. It HAS a version number and name
echo  3. We CAN dump its firmware
echo  4. That firmware IS a complete operating system
echo  5. It runs on a SECRET processor
echo.
echo ================================================================
echo.
echo  STEP 1: Find the hidden device (screenshot this)
echo  ---------------------------------------------------------------
echo.
wmic path Win32_PnPEntity where "DeviceID like '%%VEN_8086%%'" get Name, DeviceID /format:list 2>nul | findstr /C:"MEI" /C:"ME" /C:"1E"
echo.
echo  [That device above IS the secret computer]
echo.
pause

@echo off
title Intel ME - Step 2: The Secret Computer Speaks
color 0A
cls
echo ================================================================
echo   STEP 2: THE SECRET COMPUTER IDENTIFIES ITSELF
echo ================================================================
echo.
echo  Running Intel MEInfo as administrator...
echo  This tool talks DIRECTLY to the hidden processor.
echo.
echo  The output below comes from the ME itself, NOT from Windows.
echo.
echo ================================================================
echo.
"%~dp0..\IntelME_Tools\MEInfoWin64_v16.1.exe" 2>nul
echo.
echo ================================================================
echo  ^> See "Version: 16.0.15.1735"?
echo  ^> That's the VERSION NUMBER of the secret operating system.
echo  ^> Your Windows has a version. This has its OWN version.
echo  ^> It was built on 2022-02-17 and you never knew it existed.
echo ================================================================
echo.
pause

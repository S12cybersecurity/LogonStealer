@echo off
setlocal enabledelayedexpansion

set CLSID_CP={5C1B3A2D-7F4E-4B0C-9D6E-8F2A1C3B5D7E}

echo.
echo Unregistering Credential Provider...
echo   CLSID: %CLSID_CP%
echo.

net session >nul 2>&1
if %errorlevel% neq 0 (
  echo ERROR: Must run as Administrator.
  exit /b 1
)

set REG_EXE=%SystemRoot%\System32\reg.exe
if exist %SystemRoot%\Sysnative\reg.exe set REG_EXE=%SystemRoot%\Sysnative\reg.exe

"%REG_EXE%" delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\%CLSID_CP%" /f >nul 2>&1
"%REG_EXE%" delete "HKCR\CLSID\%CLSID_CP%" /f >nul 2>&1

echo SUCCESS: Credential Provider unregistered.
echo - Sign out or reboot to fully unload the DLL.
echo.
exit /b 0

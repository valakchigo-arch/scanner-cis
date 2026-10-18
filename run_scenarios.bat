@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
title GeoThread DJBC - Windows Scenario Testing

REM ============================================================
REM SCENARIO 1 - Screen Lock (P0-2: HKLM InactivityTimeoutSecs)
REM CIS 2.3.7.4 "Interactive logon: Machine inactivity limit"
REM ============================================================
call :header "SCENARIO 1 - Screen Lock Timeout (HKLM InactivityTimeoutSecs)"
call :run_scan before_screenlock
set SLKEY=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
set SLVAL=InactivityTimeoutSecs
reg add "%SLKEY%" /v %SLVAL% /t REG_DWORD /d 1800 /f >nul 2>&1
call :sleep
call :run_scan after_screenlock_1800
reg add "%SLKEY%" /v %SLVAL% /t REG_DWORD /d 901 /f >nul 2>&1
call :sleep
call :run_scan after_screenlock_901
reg add "%SLKEY%" /v %SLVAL% /t REG_DWORD /d 900 /f >nul 2>&1
call :sleep
call :run_scan after_screenlock_900
reg add "%SLKEY%" /v %SLVAL% /t REG_DWORD /d 0 /f >nul 2>&1
call :sleep
call :run_scan after_screenlock_0
reg add "%SLKEY%" /v %SLVAL% /t REG_DWORD /d 1 /f >nul 2>&1
call :sleep
call :run_scan after_screenlock_1
reg delete "%SLKEY%" /v %SLVAL% /f >nul 2>&1
call :sleep
call :run_scan rollback_screenlockREM ============================================================
REM BASELINE
REM ============================================================
call :header "BASELINE"
call :run_scan baseline

REM ============================================================
REM SCENARIO 1 - Screen Lock Timeout
REM ============================================================
call :header "SCENARIO 1 - Screen Lock Timeout 1800s"
call :run_scan before_screenlock
echo [CHANGE] ScreenSaveTimeOut=1800
reg add "HKCU\Control Panel\Desktop" /v ScreenSaveTimeOut /t REG_SZ /d 1800 /f >nul
call :sleep
call :run_scan after_screenlock_1800
echo [EXPECT] WIN-SCREENLOCK-TIMEOUT = FAIL
echo [ROLLBACK] delete ScreenSaveTimeOut
reg delete "HKCU\Control Panel\Desktop" /v ScreenSaveTimeOut /f >nul 2>&1
call :sleep
call :run_scan rollback_screenlock

REM ============================================================
REM SCENARIO 2 - Password Min Length
REM ============================================================
call :header "SCENARIO 2 - Password MinLength 8"
call :run_scan before_minlen
echo [CHANGE] minpwlen=8
net accounts /minpwlen:8 >nul 2>&1
call :sleep
call :run_scan after_minlen_8
echo [EXPECT] WIN-PASS-MINLEN = FAIL
echo [ROLLBACK] minpwlen=0
net accounts /minpwlen:0 >nul 2>&1
call :sleep
call :run_scan rollback_minlen

REM ============================================================
REM SCENARIO 3 - Lockout Threshold
REM ============================================================
call :header "SCENARIO 3 - Lockout Threshold 0"
call :run_scan before_lockout
echo [CHANGE] lockoutthreshold=0
net accounts /lockoutthreshold:0 >nul 2>&1
call :sleep
call :run_scan after_lockout_0
echo [EXPECT] WIN-ACCT-LOCKOUT = FAIL
echo [ROLLBACK] lockoutthreshold=10
net accounts /lockoutthreshold:10 >nul 2>&1
call :sleep
call :run_scan rollback_lockout

REM ============================================================
REM SCENARIO 4 - Guest Account
REM ============================================================
call :header "SCENARIO 4 - Guest Account Enabled"
call :run_scan before_guest
echo [CHANGE] guest /active:yes
net user guest /active:yes >nul 2>&1
call :sleep
call :run_scan after_guest_on
echo [EXPECT] WIN-GUEST-DISABLED = FAIL
echo [ROLLBACK] guest /active:no
net user guest /active:no >nul 2>&1
call :sleep
call :run_scan rollback_guest

REM ============================================================
REM SCENARIO 5 - Remote Registry
REM ============================================================
call :header "SCENARIO 5 - Remote Registry Enabled"
call :run_scan before_remotereg
echo [CHANGE] RemoteRegistry start= auto
sc.exe config RemoteRegistry start= auto >nul 2>&1
net start RemoteRegistry >nul 2>&1
call :sleep
call :run_scan after_remotereg_on
echo [EXPECT] WIN-REMOTEREG-DISABLED = FAIL
echo [ROLLBACK] RemoteRegistry disabled
net stop RemoteRegistry >nul 2>&1
sc.exe config RemoteRegistry start= disabled >nul 2>&1
call :sleep
call :run_scan rollback_remotereg

REM ============================================================
REM SCENARIO 6 - Firewall Private
REM ============================================================
call :header "SCENARIO 6 - Firewall Private OFF"
call :run_scan before_fw_private
echo [CHANGE] netsh privateprofile state off
netsh advfirewall set privateprofile state off >nul 2>&1
call :sleep
call :run_scan after_fw_private_off
echo [EXPECT] WIN-FW-PRIVATE = FAIL
echo [ROLLBACK] netsh privateprofile state on
netsh advfirewall set privateprofile state on >nul 2>&1
call :sleep
call :run_scan rollback_fw_private

REM ============================================================
REM SCENARIO 7 - Firewall Public
REM ============================================================
call :header "SCENARIO 7 - Firewall Public OFF"
call :run_scan before_fw_public
echo [CHANGE] netsh publicprofile state off
netsh advfirewall set publicprofile state off >nul 2>&1
call :sleep
call :run_scan after_fw_public_off
echo [EXPECT] WIN-FW-PUBLIC = FAIL
echo [ROLLBACK] netsh publicprofile state on
netsh advfirewall set publicprofile state on >nul 2>&1
call :sleep
call :run_scan rollback_fw_public

REM ============================================================
REM SCENARIO 8 - LMHash
REM ============================================================
call :header "SCENARIO 8 - LMHash Enabled (NoLMHash=0)"
call :run_scan before_lmhash
echo [CHANGE] NoLMHash=0
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash /t REG_DWORD /d 0 /f >nul
call :sleep
call :run_scan after_lmhash_0
echo [EXPECT] WIN-LMHASH-DISABLED = FAIL
echo [ROLLBACK] NoLMHash=1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f >nul
call :sleep
call :run_scan rollback_lmhash

REM ============================================================
REM SCENARIO 9 - RDP NLA
REM ============================================================
call :header "SCENARIO 9 - RDP NLA Disabled"
call :run_scan before_rdp_nla
echo [CHANGE] UserAuthentication=0
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f >nul
call :sleep
call :run_scan after_rdp_nla_off
echo [EXPECT] WIN-RDP-NLA = FAIL
echo [ROLLBACK] UserAuthentication=1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f >nul
call :sleep
call :run_scan rollback_rdp_nla

REM ============================================================
REM SCENARIO 10 - Password Complexity (via secedit)
REM ============================================================
call :header "SCENARIO 10 - Password Complexity Disabled"
call :run_scan before_complex

echo [BASELINE] PasswordComplexity via secedit
set SECPOL=%TEMP%\secpol_orig_complex.inf
set SECPOL_MOD=%TEMP%\secpol_mod_complex.inf
secedit /export /cfg "%SECPOL%" >nul 2>&1
copy "%SECPOL%" "%SECPOL_MOD%" >nul 2>&1
for /f "tokens=3" %%a in ('findstr /i "PasswordComplexity" "%SECPOL%"') do set ORIG_COMPLEX=%%a
echo [INFO] Complexity baseline = %ORIG_COMPLEX%
echo [CHANGE] PasswordComplexity=1 via secedit
powershell -Command "(Get-Content '%SECPOL_MOD%') -replace 'PasswordComplexity = %ORIG_COMPLEX%', 'PasswordComplexity = 1' | Set-Content '%SECPOL_MOD%'"
secedit /configure /db "%TEMP%\secedit_complex.sdb" /cfg "%SECPOL_MOD%" /areas SECURITYPOLICY >nul 2>&1
call :sleep
call :run_scan after_complex_on

echo [ROLLBACK] restore PasswordComplexity=%ORIG_COMPLEX%
secedit /configure /db "%TEMP%\secedit_complex.sdb" /cfg "%SECPOL%" /areas SECURITYPOLICY >nul 2>&1
del "%SECPOL%" "%SECPOL_MOD%" "%TEMP%\secedit_complex.sdb" >nul 2>&1
call :sleep
call :run_scan rollback_complex

REM ============================================================
REM SCENARIO 11 - UAC (registry only, no reboot)
REM ============================================================
call :header "SCENARIO 11 - UAC Disabled (registry only)"
echo [NOTE] Mengubah registry UAC. TIDAK akan reboot.
echo        Setelah skenario ini, WAJIB rollback (otomatis).
call :run_scan before_uac
echo [CHANGE] EnableLUA=0
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f >nul
call :sleep
call :run_scan after_uac_off
echo [EXPECT] WIN-UAC-ENABLED = FAIL
echo [ROLLBACK] EnableLUA=1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f >nul
call :sleep
call :run_scan rollback_uac

REM ============================================================
REM SKIPPED SCENARIOS
REM ============================================================
call :header "SKIPPED SCENARIOS"
echo.
echo [SKIP] WIN-FW-DOMAIN  - butuh domain-joined machine
echo [SKIP] WIN-SMB1       - butuh reboot (Enable-WindowsOptionalFeature)
echo [SKIP] WIN-DEFENDER   - tamper protection biasanya block
echo.

REM ============================================================
REM SUMMARY
REM ============================================================
call :header "SUMMARY"
echo.
call :summarize

echo.
echo ============================================================
echo SELESAI
echo ============================================================
echo.
echo Log lengkap:  %LOG%
echo JSON output:  %SCENARIOS%
echo.
echo Next steps:
echo   1. Baca %LOG% untuk detail tiap scan
echo   2. Bandingkan rollback_*.json dengan baseline
echo      (harus IDENTIK kalau rollback sukses)
echo   3. Bandingkan after_*.json dengan expected
echo.

echo. >> "%LOG%"
echo ============================================================ >> "%LOG%"
echo Finished: %date% %time% >> "%LOG%"
echo ============================================================ >> "%LOG%"

pause
exit /b 0

REM ============================================================
REM SUBROUTINES
REM ============================================================

:header
echo.
echo.
echo ============================================================
echo %~1
echo ============================================================
echo. >> "%LOG%"
echo. >> "%LOG%"
echo ============================================================ >> "%LOG%"
echo %~1 >> "%LOG%"
echo ============================================================ >> "%LOG%"
goto :eof

:run_scan
set LABEL=%~1
echo.
echo [SCAN] %LABEL%
echo. >> "%LOG%"
echo --- SCAN: %LABEL% at %time% --- >> "%LOG%"

"%PYTHON%" run_rules_live.py --label %LABEL% >> "%LOG%" 2>&1
set RC=!errorlevel!
if !RC! neq 0 (
    echo [WARN] scan exit code = !RC!
)

REM Copy newest JSON to scenarios/<label>.json
dir /b /o-d "%RESULTS%\*.json" > "%TEMP%\_latest.txt" 2>nul
set LATEST=
set /p LATEST=<"%TEMP%\_latest.txt"
if defined LATEST (
    copy "%RESULTS%\!LATEST!" "%SCENARIOS%\%LABEL%.json" >nul 2>&1
    echo [OK] saved: %LABEL%.json
) else (
    echo [WARN] no JSON output found
)
del "%TEMP%\_latest.txt" >nul 2>&1
goto :eof

:sleep
ping 127.0.0.1 -n 3 >nul 2>&1
goto :eof

:summarize
"%PYTHON%" "%~dp0summarize_scenarios.py"
goto :eof


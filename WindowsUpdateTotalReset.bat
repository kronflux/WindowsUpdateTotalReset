@cls
@echo off
setlocal enableextensions

:: BatchGotAdmin
:-------------------------------------
REM  --> Check for permissions
IF "%PROCESSOR_ARCHITECTURE%" EQU "amd64" (
IF EXIST "%SYSTEMROOT%\SysWOW64\cacls.exe" (
IF EXIST "%SYSTEMROOT%\SysWOW64\config\system" (
>nul 2>&1 "%SYSTEMROOT%\SysWOW64\cacls.exe" "%SYSTEMROOT%\SysWOW64\config\system"
) ELSE (
>nul 2>&1 "%SYSTEMROOT%\SysWOW64\cacls.exe" "%SYSTEMROOT%\System32\config\system"
)) ELSE (
>nul 2>&1 "%SYSTEMROOT%\System32\cacls.exe" "%SYSTEMROOT%\System32\config\system"
))

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"=""
    echo UAC.ShellExecute "cmd.exe", "/c ""%~s0"" %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
    pushd "%CD%"
    CD /D "%~dp0"
:--------------------------------------
echo.
echo ===============================================
echo Complete Windows Update Reset Script
echo ===============================================
echo.
echo Press any key to run the script, or close
echo window to exit.
pause >nul 2>&1
echo Resetting Windows Update...
echo.
echo 1. Stopping Windows Update, BITS, Application Identity, Cryptographic Services and SMS Host Agent services...
net stop appidsvc
net stop bits
net stop ccmexec
net stop cryptsvc
net stop wuauserv

echo 2. Checking if services were stopped successfully...
sc query wuauserv | findstr /I /C:"STOPPED"
if %errorlevel% NEQ 0 goto END

sc query bits | findstr /I /C:"STOPPED"
if %errorlevel% NEQ 0 goto END

sc query appidsvc | findstr /I /C:"STOPPED"
if %errorlevel% NEQ 0 sc query appidsvc | findstr /I /C:"OpenService FAILED 1060"
if %errorlevel% NEQ 0 goto END

sc query cryptsvc | findstr /I /C:"STOPPED"
if %errorlevel% NEQ 0 goto END

sc query ccmexec | findstr /I /C:"STOPPED"
if %errorlevel% NEQ 0 sc query ccmexec | findstr /I /C:"OpenService FAILED 1060"
if %errorlevel% NEQ 0 goto END

echo 3. Deleting AU cache folder and log file... 
del /f /q "%ALLUSERSPROFILE%\Application Data\Microsoft\Network\Downloader\qmgr*.dat"
del /f /s /q %SystemRoot%\SoftwareDistribution\*.* 
del /f /s /q %SystemRoot%\system32\catroot2\*.*

if exist "%SYSTEMROOT%\winsxs\pending.xml.bak" (
    del /s /q /f "%SYSTEMROOT%\winsxs\pending.xml.bak"
)
if exist "%SYSTEMROOT%\winsxs\pending.xml.bak" (
    del /s /q /f "%SYSTEMROOT%\winsxs\pending.xml.bak"
)
if exist "%SYSTEMROOT%\SoftwareDistribution.bak" (
    rmdir /s /q "%SYSTEMROOT%\SoftwareDistribution.bak"
)
if exist "%SYSTEMROOT%\system32\Catroot2.bak" (
    rmdir /s /q "%SYSTEMROOT%\system32\Catroot2.bak"
)
if exist "%SYSTEMROOT%\WindowsUpdate.log.bak" (
    del /s /q /f "%SYSTEMROOT%\WindowsUpdate.log.bak"
)

if exist "%SYSTEMROOT%\winsxs\pending.xml" (
    takeown /f "%SYSTEMROOT%\winsxs\pending.xml"
    attrib -r -s -h /s /d "%SYSTEMROOT%\winsxs\pending.xml"
    ren "%SYSTEMROOT%\winsxs\pending.xml" pending.xml.bak
)
if exist "%SYSTEMROOT%\SoftwareDistribution" (
    attrib -r -s -h /s /d "%SYSTEMROOT%\SoftwareDistribution"
    ren "%SYSTEMROOT%\SoftwareDistribution" SoftwareDistribution.bak
)
if exist "%SYSTEMROOT%\system32\Catroot2" (
    attrib -r -s -h /s /d "%SYSTEMROOT%\system32\Catroot2"
    ren "%SYSTEMROOT%\system32\Catroot2" Catroot2.bak
)
if exist "%SYSTEMROOT%\WindowsUpdate.log" (
    attrib -r -s -h /s /d "%SYSTEMROOT%\WindowsUpdate.log"
    ren "%SYSTEMROOT%\WindowsUpdate.log" WindowsUpdate.log.bak
)

sc.exe sdset bits D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)
sc.exe sdset wuauserv D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)

echo 4. Re-registering DLL files...
%windir%\system32\regsvr32.exe /s %windir%\system32\actxprxy.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\atl.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\browseui.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\cryptdlg.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\dssenh.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\gpkcsp.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\initpki.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\jscript.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\mshtml.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\Msjava.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\Mssip32.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\msxml.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\msxml2.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\msxml3.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\msxml6.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\muweb.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\ole32.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\oleaut32.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\qmgr.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\qmgrprxy.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\rsaenh.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\sccbase.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\scrrun.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\shdocvw.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\shell32.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\slbcsp.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\softpub.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\urlmon.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\vbscript.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\wintrust.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\wuapi.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\wuaueng.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\wuaueng1.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\wucltui.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\wucltux.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\wudriver.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\wups.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\wups2.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\wuweb.dll
%windir%\system32\regsvr32.exe /s %windir%\system32\wuwebv.dll

echo 5. Removing WSUS Client Id...
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v AccountDomainSid /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v PingID /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v SusClientId /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /f
reg delete "HKLM\COMPONENTS\PendingXmlIdentifier" /f
reg delete "HKLM\COMPONENTS\NextQueueEntryIndex" /f
reg delete "HKLM\COMPONENTS\AdvancedInstallersNeedResolving" /f

echo 6. Resetting Winsock and WinHTTP Proxy...
netsh winsock reset
proxycfg.exe -d
netsh winhttp reset proxy
ipconfig /flushdns
proxycfg.exe -d >nul 2>&1

echo 7. Starting SMS Host Agent, Cryptographic Services, Application Identity, BITS, Windows Update services...
net start appidsvc
net start bits
net start ccmexec
net start cryptsvc
net start wuauserv

echo 8. Deleting all BITS jobs...
bitsadmin.exe /reset /allusers
powershell -Command "& {import-module bitstransfer;Get-BitsTransfer -AllUsers | Remove-BitsTransfer;}"
wsreset.exe >nul 2>&1

echo 9. Forcing AU discovery...
wuauclt /resetauthorization /detectnow

:END
echo Reset Complete!
echo Press any key to exit!
pause >nul 2>&1
endlocal
exit

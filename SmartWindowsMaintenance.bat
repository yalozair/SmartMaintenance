@echo off
chcp 65001
:: ===========================================================
:: ملف: SmartWindowsMaintenancePlus.bat
:: إعداد وتخصيص: يوسف العزير✨
:: Mobile: +967773640964
:: حقوق النشر محفوظة © 2025 - يمنع إعادة التوزيع بدون إذن
:: للاستخدام الشخصي أو الفني ضمن فرق الدعم الداخلي فقط
:: ===========================================================

:: تحديث تلقائي للأداة
::set "SCRIPT_URL=https://raw.githubusercontent.com/user/repo/main/SmartWindowsMaintenancePlus.bat"
::PowerShell -Command "if((Invoke-WebRequest -Uri '%SCRIPT_URL%' -UseBasicParsing).Content -ne (Get-Content -Path '%~f0' -Raw)) { (New-Object System.Net.WebClient).DownloadFile('%SCRIPT_URL%', '%~f0') && echo ✅ تم تحديث الأداة بنجاح! && timeout /t 3 && start "" "%~f0" && exit }"

:: Force Admin Mode
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Detect Windows Version
for /f "tokens=4-5 delims=[]. " %%i in ('ver') do set winVer=%%i.%%j
set winName=Unknown Windows Version

if "%winVer%"=="5.1" set winName=Windows XP
if "%winVer%"=="6.0" set winName=Windows Vista
if "%winVer%"=="6.1" set winName=Windows 7
if "%winVer%"=="6.2" set winName=Windows 8
if "%winVer%"=="6.3" set winName=Windows 8.1
if "%winVer%"=="10.0" set winName=Windows 10/11

echo Detected OS: %winName%

:: Warn for unsupported systems
if "%winVer%"=="5.1" (
  echo ====================================================
  echo WARNING: Windows XP detected. Some features will be disabled.
  echo ====================================================
  pause
)

if "%winVer%"=="6.0" (
  echo ====================================================
  echo WARNING: Windows Vista detected. Some features may not work.
  echo ====================================================
  pause
)

title Smart Windows Maintenance Plus - Eng:Yousif Alozair 🔧
color 0A

:MAIN
cls

echo 		=====================================================================
echo 					File: SmartWindowsMaintenancePlus.bat
echo 	 		Created and customized by: Yousif Alozair © 2025
echo							Mobile: +967773640964
echo 		All rights reserved. Redistribution is prohibited without permission.
echo  			For internal technical use or personal maintenance only.
echo 		=====================================================================

echo:
echo:

echo ===========================================
echo        Smart Windows Maintenance Plus
echo ===========================================
echo [1] Basic Cleanup Tasks
echo [2] System Diagnostics
if not "%winVer%"=="5.1" if not "%winVer%"=="6.0" (
    echo [3] Network Tools
    echo [4] Windows Update Tools
)
echo [5] System Info And Utilities
echo [6] Security Center
echo [7] System Restore Points
echo [8] Printers Troubleshooting
echo [9] Storage Analysis
echo [10] Update SmartWindowsMaintenance
echo [0] Exit
echo.
set /p opt= Choose an option [0-9]: 

if "%opt%"=="1" goto CLEAN
if "%opt%"=="2" goto DIAG
if "%opt%"=="3" if not "%winVer%"=="5.1" if not "%winVer%"=="6.0" goto NET
if "%opt%"=="4" if not "%winVer%"=="5.1" if not "%winVer%"=="6.0" goto UPDATE
if "%opt%"=="5" goto INFO
if "%opt%"=="6" goto SECURITY
if "%opt%"=="7" goto RESTORE
if "%opt%"=="8" goto PRINTERS
if "%opt%"=="9" goto STORAGE
if "%opt%"=="10" goto UpdateTool
if "%opt%"=="0" exit
::goto MAIN

:CLEAN
cls

echo 		=====================================================================
echo 					File: SmartWindowsMaintenancePlus.bat
echo 	 		Created and customized by: Yousif Alozair © 2025
echo							Mobile: +967773640964
echo 		All rights reserved. Redistribution is prohibited without permission.
echo  			For internal technical use or personal maintenance only.
echo 		=====================================================================
echo:
echo:

echo --- Basic Cleanup Tasks ---
echo [1] Clean Temp Files (Safe Mode)
echo [2] Empty Recycle Bin
echo [3] Clear Prefetch Files
echo [4] Clean System Cache
echo [0] Back
echo.
set /p c= Choose cleanup option [0-4]:

if "%c%"=="1" (
  echo Cleaning Temp...
  echo [%date% %time%] Clean Temp started >> "%userprofile%\Desktop\MaintenanceLog.txt"
  
  :: حذف آمن للملفات المؤقتة
  if exist "%temp%\*.tmp" del /s /f /q "%temp%\*.tmp"
  if exist "%temp%\*.log" del /s /f /q "%temp%\*.log"
  if exist "%temp%\*.bak" del /s /f /q "%temp%\*.bak"
  if exist "C:\Windows\Temp\*.tmp" del /s /f /q "C:\Windows\Temp\*.tmp"
  
  echo [%date% %time%] Temp files deleted >> "%userprofile%\Desktop\MaintenanceLog.txt"
  ping localhost -n 2 >nul
)

if "%c%"=="2" (
  echo Emptying Recycle Bin...
  echo [%date% %time%] Empty Recycle Bin started >> "%userprofile%\Desktop\MaintenanceLog.txt"
  PowerShell -Command "Clear-RecycleBin -Force"
  echo [%date% %time%] Recycle Bin cleared >> "%userprofile%\Desktop\MaintenanceLog.txt"
  ping localhost -n 2 >nul
)

if "%c%"=="3" (
  echo Clearing Prefetch...
  echo [%date% %time%] Clear Prefetch started >> "%userprofile%\Desktop\MaintenanceLog.txt"
  del /s /f /q C:\Windows\Prefetch\*.* >nul
  echo [%date% %time%] Prefetch folder cleaned >> "%userprofile%\Desktop\MaintenanceLog.txt"
  ping localhost -n 2 >nul
)

if "%c%"=="4" (
  echo Cleaning System Cache...
  echo [%date% %time%] Clean System Cache started >> "%userprofile%\Desktop\MaintenanceLog.txt"
  
  :: تنظيف ذاكرة التخزين المؤقت لأنظمة حديثة
  if not "%winVer%"=="5.1" if not "%winVer%"=="6.0" (
    PowerShell -Command "Start-Process 'cleanmgr.exe' -ArgumentList '/sagerun:1' -Wait"
  )
  
  :: تنظيف ذاكرة التخزين المؤقت لأنظمة قديمة
  if exist "%SystemRoot%\system32\rundll32.exe" (
    "%SystemRoot%\system32\rundll32.exe" advapi32.dll,ProcessIdleTasks
  )
  
  echo [%date% %time%] System cache cleaned >> "%userprofile%\Desktop\MaintenanceLog.txt"
  ping localhost -n 2 >nul
)

if "%c%"=="0" goto MAIN
goto CLEAN

:DIAG
cls

echo 		=====================================================================
echo 					File: SmartWindowsMaintenancePlus.bat
echo 	 		Created and customized by: Yousif Alozair © 2025
echo							Mobile: +967773640964
echo 		All rights reserved. Redistribution is prohibited without permission.
echo  			For internal technical use or personal maintenance only.
echo 		=====================================================================

echo:
echo:

echo --- System Diagnostics ---
echo [1] Run SFC (System File Check)
if not "%winVer%"=="5.1" if not "%winVer%"=="6.0" (
    echo [2] Run DISM (Restore Windows Image)
)
echo [3] Run CHKDSK (Check Disk Health)
echo [4] Memory Diagnostics
echo [0] Back
echo.
set /p r= Choose diagnostic option [0-4]:

if "%r%"=="1" (
  echo Running SFC...
  echo [%date% %time%] SFC started >> "%userprofile%\Desktop\MaintenanceLog.txt"
  sfc /scannow
  echo [%date% %time%] SFC completed >> "%userprofile%\Desktop\MaintenanceLog.txt"
)

if "%r%"=="2" (
  if "%winVer%"=="5.1" goto DIAG_BLOCK
  if "%winVer%"=="6.0" goto DIAG_BLOCK
  echo Running DISM...
  echo [%date% %time%] DISM started >> "%userprofile%\Desktop\MaintenanceLog.txt"
  DISM /Online /Cleanup-Image /RestoreHealth
  echo [%date% %time%] DISM completed >> "%userprofile%\Desktop\MaintenanceLog.txt"
)

if "%r%"=="3" (
  echo Running CHKDSK...
  echo [%date% %time%] CHKDSK started >> "%userprofile%\Desktop\MaintenanceLog.txt"
  chkdsk C: /f /r
  echo [%date% %time%] CHKDSK completed >> "%userprofile%\Desktop\MaintenanceLog.txt"
)

if "%r%"=="4" (
  echo Running Memory Diagnostics...
  echo [%date% %time%] Memory Diagnostics started >> "%userprofile%\Desktop\MaintenanceLog.txt"
  PowerShell -Command "Start-Process 'mdsched.exe'"
)

if "%r%"=="0" goto MAIN
goto DIAG

:DIAG_BLOCK
echo ❌ DISM not supported on your version of Windows (%winName%)
pause
goto DIAG

:NET
cls

echo 		=====================================================================
echo 					File: SmartWindowsMaintenancePlus.bat
echo 	 		Created and customized by: Yousif Alozair © 2025
echo							Mobile: +967773640964
echo 		All rights reserved. Redistribution is prohibited without permission.
echo  			For internal technical use or personal maintenance only.
echo 		=====================================================================

echo:
echo:

echo --- Network Tools ---
echo [1] Flush DNS Cache
echo [2] Reset IP Configuration
echo [3] Reset Winsock
echo [4] Network Speed Test
echo [5] Check Internet Connection
echo [0] Back
echo.
set /p n= Choose network option [0-5]:

if "%n%"=="1" (
  echo Flushing DNS...
  echo [%date% %time%] Flush DNS started >> "%userprofile%\Desktop\MaintenanceLog.txt"
  ipconfig /flushdns
  echo [%date% %time%] DNS cache flushed >> "%userprofile%\Desktop\MaintenanceLog.txt"
)

if "%n%"=="2" (
  echo Resetting IP...
  echo [%date% %time%] Reset IP started >> "%userprofile%\Desktop\MaintenanceLog.txt"
  netsh int ip reset
  echo [%date% %time%] IP configuration reset >> "%userprofile%\Desktop\MaintenanceLog.txt"
)

if "%n%"=="3" (
  echo Resetting Winsock...
  echo [%date% %time%] Reset Winsock started >> "%userprofile%\Desktop\MaintenanceLog.txt"
  netsh winsock reset
  echo [%date% %time%] Winsock reset completed >> "%userprofile%\Desktop\MaintenanceLog.txt"
)

if "%n%"=="4" (
  echo Running Network Speed Test...
  echo [%date% %time%] Network speed test started >> "%userprofile%\Desktop\MaintenanceLog.txt"
  PowerShell -Command "Invoke-WebRequest -Uri 'https://speedtest.net' | Out-Null; (New-Object Net.WebClient).DownloadString('https://fast.com') | Out-Null"
  echo [%date% %time%] Network speed test completed >> "%userprofile%\Desktop\MaintenanceLog.txt"
)

if "%n%"=="5" (
  echo Checking Internet Connection...
  echo [%date% %time%] Internet check started >> "%userprofile%\Desktop\MaintenanceLog.txt"
  ping 8.8.8.8 -n 4
  if %errorlevel%==0 (
    echo Internet connection is active
  ) else (
    echo No internet connection
  )
  echo [%date% %time%] Internet check completed >> "%userprofile%\Desktop\MaintenanceLog.txt"
)

if "%n%"=="0" goto MAIN
goto NET

:UPDATE
cls
echo 		=====================================================================
echo 					File: SmartWindowsMaintenancePlus.bat
echo 	 		Created and customized by: Yousif Alozair © 2025
echo							Mobile: +967773640964
echo 		All rights reserved. Redistribution is prohibited without permission.
echo  			For internal technical use or personal maintenance only.
echo 		=====================================================================

echo:
echo:

echo --- Windows Update Tools ---
echo [1] Clear Update Cache
echo [2] Repair Update Services
echo [3] Enable Updates
echo [4] Disable Updates

if "%winVer%"=="6.1" (
    echo [5] Fix Windows 7 Update Problems
)

echo [6] Install Critical Updates Only
echo [0] Back
echo.
set /p up= Choose [0-6]:

if "%up%"=="1" (
    echo [%date% %time%] Clear Update Cache started >> "%userprofile%\Desktop\MaintenanceLog.txt"
    net stop wuauserv
    net stop bits
    rd /s /q %windir%\SoftwareDistribution
    net start wuauserv
    net start bits
    echo [%date% %time%] Update cache cleared >> "%userprofile%\Desktop\MaintenanceLog.txt"
)

if "%up%"=="2" (
    echo [%date% %time%] Repair Update Services started >> "%userprofile%\Desktop\MaintenanceLog.txt"
    net stop wuauserv
    net stop bits
    net stop cryptsvc
    net stop msiserver
    rd /s /q %windir%\SoftwareDistribution
    rd /s /q %windir%\System32\catroot2
    net start wuauserv
    net start bits
    net start cryptsvc
    net start msiserver
    PowerShell -Command "(New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow()"
    echo [%date% %time%] Update services repaired >> "%userprofile%\Desktop\MaintenanceLog.txt"
)

if "%up%"=="3" (
    echo [%date% %time%] Enable Updates started >> "%userprofile%\Desktop\MaintenanceLog.txt"
    sc config wuauserv start= auto
    net start wuauserv
    echo [%date% %time%] Updates enabled >> "%userprofile%\Desktop\MaintenanceLog.txt"
)

if "%up%"=="4" (
    echo [%date% %time%] Disable Updates started >> "%userprofile%\Desktop\MaintenanceLog.txt"
    net stop wuauserv
    sc config wuauserv start= disabled
    echo [%date% %time%] Updates disabled >> "%userprofile%\Desktop\MaintenanceLog.txt"
)

if "%up%"=="5" (
    if not "%winVer%"=="6.1" (
        echo ❌ This fix is only available for Windows 7 systems.
        pause
        goto UPDATE
    )
    echo [%date% %time%] Windows 7 update fix started >> "%userprofile%\Desktop\MaintenanceLog.txt"
    call :FIX_WIN7_UPDATE
    echo [%date% %time%] Windows 7 update fix completed >> "%userprofile%\Desktop\MaintenanceLog.txt"
    goto UPDATE
)

if "%up%"=="6" (
    echo [%date% %time%] Install Critical Updates started >> "%userprofile%\Desktop\MaintenanceLog.txt"
    PowerShell -Command "Get-WindowsUpdate -Install -AcceptAll -IgnoreReboot"
    echo [%date% %time%] Critical updates installed >> "%userprofile%\Desktop\MaintenanceLog.txt"
)

if "%up%"=="0" goto MAIN
goto UPDATE

:FIX_WIN7_UPDATE
    net stop wuauserv
    net stop bits
    net stop cryptsvc
    net stop msiserver
    rd /s /q %windir%\SoftwareDistribution
    rd /s /q %windir%\System32\catroot2
    for %%x in (
        atl.dll urlmon.dll mshtml.dll shdocvw.dll browseui.dll jscript.dll vbscript.dll scrrun.dll
        msxml3.dll actxprxy.dll softpub.dll wintrust.dll dssenh.dll rsaenh.dll gpkcsp.dll sccbase.dll
        slbcsp.dll cryptdlg.dll oleaut32.dll ole32.dll shell32.dll initpki.dll wuapi.dll wuaueng.dll
        wucltui.dll wups.dll wups2.dll wuweb.dll qmgr.dll qmgrprxy.dll wucltux.dll muweb.dll wuwebv.dll
    ) do regsvr32 /s %%x
    netsh winsock reset
    netsh winhttp reset proxy
    net start wuauserv
    net start bits
    net start cryptsvc
    net start msiserver
    PowerShell -Command "(New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow()"
    echo ✅ Windows 7 update repair completed.
    pause
    exit /b

:INFO
cls

echo 		=====================================================================
echo 					File: SmartWindowsMaintenancePlus.bat
echo 	 		Created and customized by: Yousif Alozair © 2025
echo							Mobile: +967773640964
echo 		All rights reserved. Redistribution is prohibited without permission.
echo  			For internal technical use or personal maintenance only.
echo 		=====================================================================

echo:
echo:

echo --- System Info And Utilities ---
echo [1] System Information Report
echo [2] CPU And Memory Management
echo [3] Startup Programs
echo [4] Drivers Management
echo [5] List Open Ports
echo [6] Disk Usage Report
echo [0] Back
echo.
set /p info_opt= Choose [0-6]:

if "%info_opt%"=="1" (
  echo Creating system info report...
  echo [%date% %time%] System info report created >> "%userprofile%\Desktop\MaintenanceLog.txt"
  systeminfo > "%userprofile%\Desktop\System_Info.txt"
  start "" "%userprofile%\Desktop\System_Info.txt"
)

if "%info_opt%"=="2" goto PERF
if "%info_opt%"=="3" goto STARTUP
if "%info_opt%"=="4" goto DRIVERS
if "%info_opt%"=="5" (
  echo Listing open ports...
  echo [%date% %time%] Open ports listed >> "%userprofile%\Desktop\MaintenanceLog.txt"
  netstat -ano
  pause
)
if "%info_opt%"=="6" (
  echo Creating disk usage report...
  echo [%date% %time%] Disk usage report created >> "%userprofile%\Desktop\MaintenanceLog.txt"
  PowerShell "Get-Volume | Format-Table DriveLetter, Size, SizeRemaining -AutoSize" > "%userprofile%\Desktop\Disk_Usage.txt"
  start "" "%userprofile%\Desktop\Disk_Usage.txt"
)

if "%info_opt%"=="0" goto MAIN
goto INFO

:PERF
echo --- CPU And Memory Management ---
echo [1] Show High-CPU Processes
echo [2] Show High-Memory Processes
echo [3] Adjust Power Plan (High Performance)
echo [4] Restart Explorer
echo [0] Back
echo.
set /p perf_opt= Choose [0-4]:

if "%perf_opt%"=="1" (
  tasklist /fi "cpuusage gt 50" /fo table
  pause
)

if "%perf_opt%"=="2" (
  PowerShell "Get-Process | Sort-Object WS -Desc | Select -First 10"
  pause
)

if "%perf_opt%"=="3" (
  powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
  echo High Performance power plan activated!
  echo [%date% %time%] Power plan set to High Performance >> "%userprofile%\Desktop\MaintenanceLog.txt"
  pause
)

if "%perf_opt%"=="4" (
  taskkill /f /im explorer.exe
  start explorer.exe
  echo Explorer restarted!
  echo [%date% %time%] Explorer restarted >> "%userprofile%\Desktop\MaintenanceLog.txt"
  pause
)

if "%perf_opt%"=="0" goto INFO
goto PERF

:STARTUP
echo --- Startup Programs Management ---
echo [1] List Startup Programs
echo [2] Disable Startup Program
echo [3] Enable Startup Program
echo [0] Back
echo.
set /p startup_opt= Choose [0-3]:

if "%startup_opt%"=="1" (
  echo Current User Startup:
  reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
  echo.
  echo All Users Startup:
  reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
  pause
)

if "%startup_opt%"=="2" (
  set /p prog_name= Enter program name to disable: 
  reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "%prog_name%" /f
  echo [%date% %time%] Startup program disabled: %prog_name% >> "%userprofile%\Desktop\MaintenanceLog.txt"
  echo Program disabled!
  pause
)

if "%startup_opt%"=="3" (
  set /p prog_name= Enter program name: 
  set /p prog_path= Enter program path: 
  reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "%prog_name%" /t REG_SZ /d "\"%prog_path%\"" /f
  echo [%date% %time%] Startup program enabled: %prog_name% >> "%userprofile%\Desktop\MaintenanceLog.txt"
  echo Program enabled!
  pause
)

if "%startup_opt%"=="0" goto INFO
goto STARTUP

:DRIVERS
echo --- Drivers Management ---
echo [1] List All Drivers
echo [2] Update Drivers via Windows Update
echo [3] Export Drivers List
echo [0] Back
echo.
set /p drv_opt= Choose [0-3]:

if "%drv_opt%"=="1" (
  driverquery /v /fo table
  pause
)

if "%drv_opt%"=="2" (
  echo Searching for driver updates...
  pnputil /scan-devices
  echo [%date% %time%] Driver update scan completed >> "%userprofile%\Desktop\MaintenanceLog.txt"
  pause
)

if "%drv_opt%"=="3" (
  driverquery > "%userprofile%\Desktop\Drivers_List.txt"
  echo [%date% %time%] Drivers list exported >> "%userprofile%\Desktop\MaintenanceLog.txt"
  start "" "%userprofile%\Desktop\Drivers_List.txt"
)

if "%drv_opt%"=="0" goto INFO
goto DRIVERS

:SECURITY
cls

echo 		=====================================================================
echo 					File: SmartWindowsMaintenancePlus.bat
echo 	 		Created and customized by: Yousif Alozair © 2025
echo							Mobile: +967773640964
echo 		All rights reserved. Redistribution is prohibited without permission.
echo  			For internal technical use or personal maintenance only.
echo 		=====================================================================

echo:
echo:

echo --- Security Center ---
echo [1] Check Windows Defender Status
echo [2] Quick Malware Scan
echo [3] Check Firewall Status
echo [4] List Admin Accounts
echo [5] Scan for Rootkits
echo [0] Back
echo.
set /p sec_opt= Choose [0-5]:

if "%sec_opt%"=="1" (
  sc query WinDefend
  echo [%date% %time%] Defender status checked >> "%userprofile%\Desktop\MaintenanceLog.txt"
  pause
)

if "%sec_opt%"=="2" (
  echo Running quick scan...
  PowerShell -Command "Start-MpScan -ScanType QuickScan"
  echo [%date% %time%] Quick malware scan completed >> "%userprofile%\Desktop\MaintenanceLog.txt"
  echo Scan completed!
  pause
)

if "%sec_opt%"=="3" (
  netsh advfirewall show allprofiles
  echo [%date% %time%] Firewall status checked >> "%userprofile%\Desktop\MaintenanceLog.txt"
  pause
)

if "%sec_opt%"=="4" (
  net localgroup administrators
  echo [%date% %time%] Admin accounts listed >> "%userprofile%\Desktop\MaintenanceLog.txt"
  pause
)

if "%sec_opt%"=="5" (
  echo Scanning for rootkits...
  if exist "%ProgramFiles%\Windows Defender\MpCmdRun.exe" (
    "%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Scan -ScanType 2
  ) else (
    echo Rootkit scan not available
  )
  echo [%date% %time%] Rootkit scan completed >> "%userprofile%\Desktop\MaintenanceLog.txt"
  pause
)

if "%sec_opt%"=="0" goto MAIN
goto SECURITY

:RESTORE
cls

echo 		=====================================================================
echo 					File: SmartWindowsMaintenancePlus.bat
echo 	 		Created and customized by: Yousif Alozair © 2025
echo							Mobile: +967773640964
echo 		All rights reserved. Redistribution is prohibited without permission.
echo  			For internal technical use or personal maintenance only.
echo 		=====================================================================

echo:
echo:

echo --- System Restore Points ---
echo [1] Create Restore Point
echo [2] List Available Restore Points
echo [3] Restore System
echo [0] Back
echo.
set /p rp_opt= Choose [0-3]:

if "%rp_opt%"=="1" (
  PowerShell "Checkpoint-Computer -Description 'SmartMaintenance Restore Point' -RestorePointType MODIFY_SETTINGS"
  echo [%date% %time%] Restore point created >> "%userprofile%\Desktop\MaintenanceLog.txt"
  echo Restore point created successfully!
  pause
)

if "%rp_opt%"=="2" (
  wmic.exe /Namespace:\\root\default Path SystemRestore Call GetRestorePoints
  echo [%date% %time%] Restore points listed >> "%userprofile%\Desktop\MaintenanceLog.txt"
  pause
)

if "%rp_opt%"=="3" (
  echo [%date% %time%] System restore initiated >> "%userprofile%\Desktop\MaintenanceLog.txt"
  rstrui.exe
)

if "%rp_opt%"=="0" goto MAIN
goto RESTORE

:PRINTERS
cls

echo 		=====================================================================
echo 					File: SmartWindowsMaintenancePlus.bat
echo 	 		Created and customized by: Yousif Alozair © 2025
echo							Mobile: +967773640964
echo 		All rights reserved. Redistribution is prohibited without permission.
echo  			For internal technical use or personal maintenance only.
echo 		=====================================================================

echo:
echo:

echo --- Printers Troubleshooting ---
echo [1] Clear Print Queue
echo [2] Restart Print Spooler
echo [3] List Installed Printers
echo [4] Set Default Printer
echo [0] Back
echo.
set /p printer_opt= Choose [0-4]:

if "%printer_opt%"=="1" (
  echo Clearing print queue...
  net stop spooler
  del /Q %systemroot%\System32\spool\printers\*.*
  net start spooler
  echo [%date% %time%] Print queue cleared >> "%userprofile%\Desktop\MaintenanceLog.txt"
  echo Print queue cleared!
  pause
)

if "%printer_opt%"=="2" (
  net stop spooler
  net start spooler
  echo [%date% %time%] Print spooler restarted >> "%userprofile%\Desktop\MaintenanceLog.txt"
  echo Print spooler restarted!
  pause
)

if "%printer_opt%"=="3" (
  wmic printer get name,portname,default
  echo [%date% %time%] Printers listed >> "%userprofile%\Desktop\MaintenanceLog.txt"
  pause
)

if "%printer_opt%"=="4" (
  set /p printer_name= Enter printer name: 
  PowerShell -Command "Set-Printer -Name '%printer_name%' -Default"
  echo [%date% %time%] Default printer set: %printer_name% >> "%userprofile%\Desktop\MaintenanceLog.txt"
  echo Default printer set!
  pause
)

if "%printer_opt%"=="0" goto MAIN
goto PRINTERS

:STORAGE
cls

echo 		=====================================================================
echo 					File: SmartWindowsMaintenancePlus.bat
echo 	 		Created and customized by: Yousif Alozair © 2025
echo							Mobile: +967773640964
echo 		All rights reserved. Redistribution is prohibited without permission.
echo  			For internal technical use or personal maintenance only.
echo 		=====================================================================

echo:
echo:

echo --- Storage Analysis ---
echo [1] Show Disk Usage
echo [2] Find Large Files (>1GB)
echo [3] Clean System Files
echo [4] Analyze Disk Space
echo [0] Back
echo.
set /p storage_opt= Choose [0-4]:

if "%storage_opt%"=="1" (
  PowerShell "Get-Volume | Format-Table DriveLetter, Size, SizeRemaining -AutoSize"
  echo [%date% %time%] Disk usage listed >> "%userprofile%\Desktop\MaintenanceLog.txt"
  pause
)

if "%storage_opt%"=="2" (
  PowerShell "Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 1GB } | Sort-Object -Property Length -Descending | Select-Object FullName, Length -First 20 > \"%userprofile%\Desktop\Large_Files.txt\""
  start "" "%userprofile%\Desktop\Large_Files.txt"
  echo [%date% %time%] Large files listed >> "%userprofile%\Desktop\MaintenanceLog.txt"
)

if "%storage_opt%"=="3" (
  if not "%winVer%"=="5.1" if not "%winVer%"=="6.0" (
    PowerShell -Command "Start-Process 'cleanmgr.exe' -ArgumentList '/sagerun:1' -Wait"
  ) else (
    echo Disk Cleanup not available
  )
  echo [%date% %time%] System files cleaned >> "%userprofile%\Desktop\MaintenanceLog.txt"
  pause
)

if "%storage_opt%"=="4" (
  PowerShell "Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | Group-Object -Property Extension | Sort-Object -Property Count -Descending | Select-Object Count, Name -First 20 > \"%userprofile%\Desktop\Disk_Analysis.txt\""
  start "" "%userprofile%\Desktop\Disk_Analysis.txt"
  echo [%date% %time%] Disk analysis completed >> "%userprofile%\Desktop\MaintenanceLog.txt"
)

if "%storage_opt%"=="0" goto MAIN
goto STORAGE


:UpdateTool

::cls

echo 		=====================================================================
echo 					File: SmartWindowsMaintenancePlus.bat
echo 	 		Created and customized by: Yousif Alozair © 2025
echo							Mobile: +967773640964
echo 		All rights reserved. Redistribution is prohibited without permission.
echo  			For internal technical use or personal maintenance only.
echo 		=====================================================================
echo:
echo:


::setlocal

::set "SCRIPT_URL=https://raw.githubusercontent.com/yalozair/SmartMaintenance/refs/heads/main/SmartWindowsMaintenance.bat"
::set "LOCAL_FILE=%~f0"

::PowerShell -Command "if ((Invoke-WebRequest -Uri '%SCRIPT_URL%' -UseBasicParsing).Content -ne (Get-Content -Path '%LOCAL_FILE%' -Raw)) { (New-Object System.Net.WebClient).DownloadFile('%SCRIPT_URL%', '%LOCAL_FILE%'); Write-Host 'تم التحديث بنجاح'; Start-Sleep -Seconds 3; Start-Process -FilePath '%LOCAL_FILE%'; exit }"

::endlocal

::pause

::goto MAIN

:: تحديث الأداة يدويًا
setlocal EnableDelayedExpansion

set "SCRIPT_URL=https://raw.githubusercontent.com/yalozair/SmartMaintenance/main/SmartWindowsMaintenancePlus.bat"
set "LOCAL_FILE=%~f0"

echo 🔍 Checking for updates to the tool...

powershell -NoProfile -Command ^
"$url='%SCRIPT_URL%'; $local='%LOCAL_FILE%'; try { $remote=(Invoke-WebRequest -Uri $url -UseBasicParsing).Content; $current=Get-Content -Path $local -Raw; if ($remote -ne $current) { Write-Host ''; Write-Host '⬇️ A new update is available... Downloading the new version...'; (New-Object Net.WebClient).DownloadFile($url, $local); Write-Host '✅ Successfully updated to the new version!'; Start-Sleep -Seconds 2; Start-Process -FilePath $local; exit } else { Write-Host '✅ The tool is already updated. There are no new updates.'; Start-Sleep -Seconds 2 } } catch { Write-Host '❌ An error occurred while trying to check for updates. Please ensure you are connected to the internet.'; Start-Sleep -Seconds 3 }"

endlocal
::pause
Exit
goto MAIN

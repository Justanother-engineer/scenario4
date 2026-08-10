$activity   = Join-Path ([Environment]::GetFolderPath('Desktop')) 'activity.log'
function Write-Activity($msg) {
    Add-Content -Path $activity -Value ("[{0}] [cleanup.ps1] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $msg) -ErrorAction SilentlyContinue
}
$svchost    = "C:\Program Files\Microsoft\svchost.exe"
$p0wershell = "C:\Windows\System32\P0wershell.exe"
$mimikatz   = "C:\Windows\System32\mimikatz.exe"
$mimilib    = "C:\Windows\System32\mimilib.dll"
$libraries  = "C:\Users\Public\Libraries"
$regPath    = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msra.exe"
$lnk        = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\msra.lnk"
$tasks      = @("GOVINDA", "Orion", "MimiDump")
$backdoor   = "support"
$logsDir    = "C:\ProgramData\USOShared\Logs"
$enumFile   = "C:\ProgramData\Microsoft\Search\Data\EDS\index.tmp"
$samFile    = "C:\ProgramData\Microsoft\Windows\WER\ReportQueue\sam.tmp"
$batFile    = "C:\Windows\Temp\mimi.bat"
$ipFile     = "C:\Windows\Temp\ip.tmp"

$body = @"
`$activity   = "$activity"
function Write-Activity(`$msg) {
    Add-Content -Path `$activity -Value ("[{0}] [cleanup.ps1] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), `$msg) -ErrorAction SilentlyContinue
}
`$svchost    = "$svchost"
`$p0wershell = "$p0wershell"
`$mimikatz   = "$mimikatz"
`$mimilib    = "$mimilib"
`$libraries  = "$libraries"
`$regPath    = "$regPath"
`$lnk        = "$lnk"
`$tasks      = @("GOVINDA", "Orion", "MimiDump")
`$backdoor   = "$backdoor"
`$logsDir    = "$logsDir"
`$enumFile   = "$enumFile"
`$samFile    = "$samFile"
`$batFile    = "$batFile"
`$ipFile     = "$ipFile"
Write-Activity "[*] cleanup started (elevated)"
# kill only our dropped processes by path. Never match by process Name — the
# OS's own C:\Windows\System32\svchost.exe would match "svchost" and kill it.
Get-Process | Where-Object { `$_.Path -eq `$svchost -or `$_.Path -eq `$p0wershell -or `$_.Path -eq `$mimikatz -or `$_.Path -like "`$(`$libraries)*" } | Stop-Process -Force -ErrorAction SilentlyContinue
Write-Activity "[+] dropped processes stopped (by path)"
# remove the backdoor account from groups then delete it (reverse of enumeration)
net.exe localgroup "Remote Desktop Users" `$backdoor /delete 2>`$null
net.exe localgroup Administrators        `$backdoor /delete 2>`$null
net.exe user `$backdoor /delete 2>`$null
Write-Activity "[+] backdoor account '`$backdoor' removed"
# re-enable the firewall the enumeration disabled
netsh.exe advfirewall set allprofiles state on | Out-Null
Write-Activity "[+] firewall re-enabled"
# revert RDP enable + remove HKCU Run key the worker added
reg.exe add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f 2>`$null
Write-Activity "[+] RDP reverted (fDenyTSConnections=1)"
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v OneDriveSync /f 2>`$null
Write-Activity "[+] HKCU Run\OneDriveSync removed"
# remove the WinUpdHlth service (EID 7045)
sc.exe delete WinUpdHlth 2>`$null
Write-Activity "[+] WinUpdHlth service deleted"
# files: never recurse-delete the legit dirs (Libraries, USOShared\Logs, EDS, WER) — remove only our files
Remove-Item -Path `$svchost -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Program Files\Microsoft" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path `$p0wershell -Force -ErrorAction SilentlyContinue
Remove-Item -Path `$mimikatz -Force -ErrorAction SilentlyContinue
Remove-Item -Path `$mimilib -Force -ErrorAction SilentlyContinue
Write-Activity "[+] exe artifacts removed (svchost.exe, P0wershell.exe, mimikatz.exe, mimilib.dll)"
Remove-Item -Path "`$libraries\msra.exe" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "`$libraries\userenv.dll" -Force -ErrorAction SilentlyContinue
Write-Activity "[+] Libraries artifacts removed (msra.exe, userenv.dll)"
Remove-Item -Path "`$logsDir\mimikatz.sha256.txt" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "`$logsDir\p0wershell.log" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "`$logsDir\p0wershell.started" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "`$logsDir\elevcheck.log" -Force -ErrorAction SilentlyContinue
Write-Activity "[+] USOShared\Logs artifacts removed (sha manifest + legacy logs)"
Remove-Item -Path `$enumFile -Force -ErrorAction SilentlyContinue
Remove-Item -Path `$samFile -Force -ErrorAction SilentlyContinue
Remove-Item -Path `$batFile -Force -ErrorAction SilentlyContinue
Remove-Item -Path `$ipFile -Force -ErrorAction SilentlyContinue
Write-Activity "[+] temp artifacts removed (index.tmp, sam.tmp, mimi.bat, ip.tmp)"
# legacy dir from the pre-scatter version + old drive-root logs
Remove-Item -Path "C:\ProgramData\Microsoft\Crypto\RSA\S-1-5-18" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\p0wershell.log" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\p0wershell.started" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\elevcheck.log" -Force -ErrorAction SilentlyContinue
Write-Activity "[+] legacy pre-scatter artifacts removed (Crypto\RSA\S-1-5-18, drive-root logs)"
Remove-Item -Path `$regPath -Recurse -Force -ErrorAction SilentlyContinue
Write-Activity "[+] registry App Paths\msra.exe removed"
Remove-Item -Path `$lnk -Force -ErrorAction SilentlyContinue
Write-Activity "[+] startup .lnk removed"
foreach (`$t in `$tasks) { schtasks.exe /delete /tn `$t /f | Out-Null }
Write-Activity "[+] scheduled tasks deleted (GOVINDA, Orion, MimiDump)"
Write-Activity "[*] cleanup complete — all artifacts removed"
Remove-Item -Path `$activity -Force -ErrorAction SilentlyContinue
Remove-Item -Path "`$PSCommandPath" -Force -ErrorAction SilentlyContinue
"@

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Write-Activity "[*] cleanup requested — not elevated, spawning elevated child via UAC (RunAs)"
    $tmp = [System.IO.Path]::GetTempFileName() + ".ps1"
    Set-Content -Path $tmp -Value $body
    Start-Process powershell.exe "-NoP -NonI -Exec Bypass -File `"$tmp`"" -Verb RunAs
    exit
}

Write-Activity "[*] cleanup started (elevated)"
# kill only our dropped processes by path. Never match by process Name — the
# OS's own C:\Windows\System32\svchost.exe would match "svchost" and kill it.
Get-Process | Where-Object { $_.Path -eq $svchost -or $_.Path -eq $p0wershell -or $_.Path -eq $mimikatz -or $_.Path -like "$libraries*" } | Stop-Process -Force -ErrorAction SilentlyContinue
Write-Activity "[+] dropped processes stopped (by path)"
# remove the backdoor account from groups then delete it (reverse of enumeration)
net.exe localgroup "Remote Desktop Users" $backdoor /delete 2>$null
net.exe localgroup Administrators        $backdoor /delete 2>$null
net.exe user $backdoor /delete 2>$null
Write-Activity "[+] backdoor account '$backdoor' removed"
# re-enable the firewall the enumeration disabled
netsh.exe advfirewall set allprofiles state on | Out-Null
Write-Activity "[+] firewall re-enabled"
# revert RDP enable + remove HKCU Run key the worker added
reg.exe add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f 2>$null
Write-Activity "[+] RDP reverted (fDenyTSConnections=1)"
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v OneDriveSync /f 2>$null
Write-Activity "[+] HKCU Run\OneDriveSync removed"
# remove the WinUpdHlth service (EID 7045)
sc.exe delete WinUpdHlth 2>$null
Write-Activity "[+] WinUpdHlth service deleted"
# files: never recurse-delete the legit dirs (Libraries, USOShared\Logs, EDS, WER) — remove only our files
Remove-Item -Path $svchost -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Program Files\Microsoft" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $p0wershell -Force -ErrorAction SilentlyContinue
Remove-Item -Path $mimikatz -Force -ErrorAction SilentlyContinue
Remove-Item -Path $mimilib -Force -ErrorAction SilentlyContinue
Write-Activity "[+] exe artifacts removed (svchost.exe, P0wershell.exe, mimikatz.exe, mimilib.dll)"
Remove-Item -Path "$libraries\msra.exe" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$libraries\userenv.dll" -Force -ErrorAction SilentlyContinue
Write-Activity "[+] Libraries artifacts removed (msra.exe, userenv.dll)"
Remove-Item -Path "$logsDir\mimikatz.sha256.txt" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$logsDir\p0wershell.log" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$logsDir\p0wershell.started" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$logsDir\elevcheck.log" -Force -ErrorAction SilentlyContinue
Write-Activity "[+] USOShared\Logs artifacts removed (sha manifest + legacy logs)"
Remove-Item -Path $enumFile -Force -ErrorAction SilentlyContinue
Remove-Item -Path $samFile -Force -ErrorAction SilentlyContinue
Remove-Item -Path $batFile -Force -ErrorAction SilentlyContinue
Remove-Item -Path $ipFile -Force -ErrorAction SilentlyContinue
Write-Activity "[+] temp artifacts removed (index.tmp, sam.tmp, mimi.bat, ip.tmp)"
# legacy dir from the pre-scatter version + old drive-root logs
Remove-Item -Path "C:\ProgramData\Microsoft\Crypto\RSA\S-1-5-18" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\p0wershell.log" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\p0wershell.started" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\elevcheck.log" -Force -ErrorAction SilentlyContinue
Write-Activity "[+] legacy pre-scatter artifacts removed (Crypto\RSA\S-1-5-18, drive-root logs)"
Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
Write-Activity "[+] registry App Paths\msra.exe removed"
Remove-Item -Path $lnk -Force -ErrorAction SilentlyContinue
Write-Activity "[+] startup .lnk removed"
foreach ($t in $tasks) { schtasks.exe /delete /tn $t /f | Out-Null }
Write-Activity "[+] scheduled tasks deleted (GOVINDA, Orion, MimiDump)"
Write-Activity "[*] cleanup complete — all artifacts removed"
Remove-Item -Path $activity -Force -ErrorAction SilentlyContinue

$svchost   = "C:\Program Files\Microsoft\svchost.exe"
$p0wershell = "C:\Windows\System32\P0wershell.exe"
$msraDir    = "C:\ProgramData\Microsoft\Crypto\RSA\S-1-5-18"
$regPath    = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msra.exe"
$lnk        = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\msra.lnk"
$tasks      = @("GOVINDA", "Orion")
$backdoor   = "support"

$body = @"
`$svchost   = "$svchost"
`$p0wershell = "$p0wershell"
`$msraDir    = "$msraDir"
`$regPath    = "$regPath"
`$lnk        = "$lnk"
`$tasks      = @("GOVINDA", "Orion")
`$backdoor   = "$backdoor"
# kill only our dropped files by path. Never match by process Name — the OS's
# own C:\Windows\System32\svchost.exe would match "svchost" and killing it
# crashes the system. Our payload runs from the paths below.
Get-Process | Where-Object { `$_.Path -eq `$svchost -or `$_.Path -eq `$p0wershell -or `$_.Path -like "`$(`$msraDir)*" } | Stop-Process -Force -ErrorAction SilentlyContinue
# remove the backdoor account from groups then delete it (reverse of enumeration)
net.exe localgroup "Remote Desktop Users" `$backdoor /delete 2>`$null
net.exe localgroup Administrators        `$backdoor /delete 2>`$null
net.exe user `$backdoor /delete 2>`$null
# re-enable the firewall the enumeration disabled
netsh.exe advfirewall set allprofiles state on | Out-Null
Remove-Item -Path `$svchost -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Program Files\Microsoft" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path `$p0wershell -Force -ErrorAction SilentlyContinue
Remove-Item -Path `$msraDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path `$regPath -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path `$lnk -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\elevcheck.log" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\p0wershell.log" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\p0wershell.started" -Force -ErrorAction SilentlyContinue
foreach (`$t in `$tasks) { schtasks.exe /delete /tn `$t /f | Out-Null }
Remove-Item -Path "`$PSCommandPath" -Force -ErrorAction SilentlyContinue
"@

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    $tmp = [System.IO.Path]::GetTempFileName() + ".ps1"
    Set-Content -Path $tmp -Value $body
    Start-Process powershell.exe "-NoP -NonI -Exec Bypass -File `"$tmp`"" -Verb RunAs
    exit
}

# kill only our dropped files by path. Never match by process Name — the OS's
# own C:\Windows\System32\svchost.exe would match "svchost" and killing it
# crashes the system. Our payload runs from the paths below.
Get-Process | Where-Object { $_.Path -eq $svchost -or $_.Path -eq $p0wershell -or $_.Path -like "$msraDir*" } | Stop-Process -Force -ErrorAction SilentlyContinue
# remove the backdoor account from groups then delete it (reverse of enumeration)
net.exe localgroup "Remote Desktop Users" $backdoor /delete 2>$null
net.exe localgroup Administrators        $backdoor /delete 2>$null
net.exe user $backdoor /delete 2>$null
# re-enable the firewall the enumeration disabled
netsh.exe advfirewall set allprofiles state on | Out-Null
Remove-Item -Path $svchost -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Program Files\Microsoft" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $p0wershell -Force -ErrorAction SilentlyContinue
Remove-Item -Path $msraDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $lnk -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\elevcheck.log" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\p0wershell.log" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\p0wershell.started" -Force -ErrorAction SilentlyContinue
foreach ($t in $tasks) { schtasks.exe /delete /tn $t /f | Out-Null }

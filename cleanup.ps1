$svchost = "C:\Program Files\Microsoft\svchost.exe"
$p0wershell = "C:\Windows\System32\P0wershell.exe"
$msraDir = "C:\ProgramData\Microsoft\Crypto\RSA\S-1-5-18"
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msra.exe"
$lnk = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\msra.lnk"
$tasks = @("GOVINDA", "Orion")

$body = @"
`$svchost = "$svchost"
`$p0wershell = "$p0wershell"
`$msraDir = "$msraDir"
`$regPath = "$regPath"
`$lnk = "$lnk"
`$tasks = @("GOVINDA", "Orion")
Get-Process | Where-Object { `$_.Path -eq `$svchost -or `$_.Path -eq `$p0wershell -or `$_.Path -like "`$(`$msraDir)*" } | Stop-Process -Force -ErrorAction SilentlyContinue
Remove-Item -Path `$svchost -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Program Files\Microsoft" -Force -ErrorAction SilentlyContinue
Remove-Item -Path `$p0wershell -Force -ErrorAction SilentlyContinue
Remove-Item -Path `$msraDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path `$regPath -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path `$lnk -Force -ErrorAction SilentlyContinue
foreach (`$t in `$tasks) { schtasks.exe /delete /tn `$t /f | Out-Null }
Remove-Item -Path `"`$PSCommandPath`" -Force -ErrorAction SilentlyContinue
"@

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    $tmp = [System.IO.Path]::GetTempFileName() + ".ps1"
    Set-Content -Path $tmp -Value $body
    Start-Process powershell.exe "-NoP -NonI -Exec Bypass -File `"$tmp`"" -Verb RunAs
    exit
}

Get-Process | Where-Object { $_.Path -eq $svchost -or $_.Path -eq $p0wershell -or $_.Path -like "$msraDir*" } | Stop-Process -Force -ErrorAction SilentlyContinue
Remove-Item -Path $svchost -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Program Files\Microsoft" -Force -ErrorAction SilentlyContinue
Remove-Item -Path $p0wershell -Force -ErrorAction SilentlyContinue
Remove-Item -Path $msraDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $lnk -Force -ErrorAction SilentlyContinue
foreach ($t in $tasks) { schtasks.exe /delete /tn $t /f | Out-Null }

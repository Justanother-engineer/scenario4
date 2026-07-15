$svchost = "C:\Program Files\Microsoft\svchost.exe"
$p0wershell = "C:\Windows\System32\P0wershell.exe"

$body = @"
`$svchost = "$svchost"
`$p0wershell = "$p0wershell"
Get-Process | Where-Object { `$_.Path -eq `$svchost -or `$_.Path -eq `$p0wershell } | Stop-Process -Force -ErrorAction SilentlyContinue
Remove-Item -Path `$svchost -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Program Files\Microsoft" -Force -ErrorAction SilentlyContinue
Remove-Item -Path `$p0wershell -Force -ErrorAction SilentlyContinue
Remove-Item -Path `"`$PSCommandPath`" -Force -ErrorAction SilentlyContinue
"@

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    $tmp = [System.IO.Path]::GetTempFileName() + ".ps1"
    Set-Content -Path $tmp -Value $body
    Start-Process powershell.exe "-NoP -NonI -Exec Bypass -File `"$tmp`"" -Verb RunAs
    exit
}

Get-Process | Where-Object { $_.Path -eq $svchost -or $_.Path -eq $p0wershell } | Stop-Process -Force -ErrorAction SilentlyContinue
Remove-Item -Path $svchost -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Program Files\Microsoft" -Force -ErrorAction SilentlyContinue
Remove-Item -Path $p0wershell -Force -ErrorAction SilentlyContinue

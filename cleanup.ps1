$dst = "C:\Program Files\Microsoft\svchost.exe"

if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell.exe "-File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Get-Process | Where-Object { $_.Path -eq $dst } | Stop-Process -Force -ErrorAction SilentlyContinue
Remove-Item -Path $dst -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Program Files\Microsoft" -Force -ErrorAction SilentlyContinue

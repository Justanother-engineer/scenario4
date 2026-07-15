$dst = "C:\Program Files\Microsoft\svchost.exe"

$body = @"
`$dst = "$dst"
Get-Process | Where-Object { `$_.Path -eq `$dst } | Stop-Process -Force -ErrorAction SilentlyContinue
Remove-Item -Path `$dst -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$([System.IO.Path]::GetDirectoryName($dst))" -Force -ErrorAction SilentlyContinue
Remove-Item -Path `"`$PSCommandPath`" -Force -ErrorAction SilentlyContinue
"@

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    $tmp = [System.IO.Path]::GetTempFileName() + ".ps1"
    Set-Content -Path $tmp -Value $body
    Start-Process powershell.exe "-NoP -NonI -Exec Bypass -File `"$tmp`"" -Verb RunAs
    exit
}

Get-Process | Where-Object { $_.Path -eq $dst } | Stop-Process -Force -ErrorAction SilentlyContinue
Remove-Item -Path $dst -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Program Files\Microsoft" -Force -ErrorAction SilentlyContinue

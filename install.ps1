New-Item -Path $profile -ItemType "file" -Force
Invoke-RestMethod https://github.com/dlsathvik04/PowerShell-Tweaks/raw/main/default.ps1 -OutFile $PROFILE
Invoke-Command { & "pwsh.exe"} -NoNewScope

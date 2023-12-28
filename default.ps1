$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

If (Test-Path "C:\ProgramData\miniconda3\Scripts\conda.exe") {
    (& "C:\ProgramData\miniconda3\Scripts\conda.exe" "shell.powershell" "hook") | Out-String | ?{$_} | Invoke-Expression
}

# If so and the current host is a command line, then change to red color 
# as warning to user that they are operating in an elevated context
# Useful shortcuts for traversing directories
function cd... { Set-Location ..\.. }
function cd.... { Set-Location ..\..\.. }

# Compute file hashes - useful for checking successful downloads 
function md5 { Get-FileHash -Algorithm MD5 $args }
function sha1 { Get-FileHash -Algorithm SHA1 $args }
function sha256 { Get-FileHash -Algorithm SHA256 $args }


function exp { explorer.exe . }

# Drive shortcuts
function HKLM: { Set-Location HKLM: }
function HKCU: { Set-Location HKCU: }
function Env: { Set-Location Env: }

# Creates drive shortcut for Work Folders, if current user account is using it
if (Test-Path "$env:USERPROFILE\Work Folders") {
    New-PSDrive -Name Work -PSProvider FileSystem -Root "$env:USERPROFILE\Work Folders" -Description "Work Folders"
    function Work: { Set-Location Work: }
}

# Set up command prompt and window title. Use UNIX-style convention for identifying 
# whether user is elevated (root) or not. Window title shows current version of PowerShell
# and appends [ADMIN] if appropriate for easy taskbar identification

# (& "C:\Anaconda3\Scripts\conda.exe" "shell.powershell" "hook") | Out-String | Invoke-Expression

Function Test-CommandExists {
    Param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    try { if (Get-Command $command) { RETURN $true } }
    Catch { Write-Host "$command does not exist"; RETURN $false }
    Finally { $ErrorActionPreference = $oldPreference }
}

function prompt { 
    if (Test-Path .git) {
        git branch | ForEach-Object {
            if ($_ -match "^\*(.*)") {
                Write-Host ("(" + $matches[1].Trim() + ")") -nonewline -foregroundcolor white -BackgroundColor red
            }
        }
    }
    
    if (Test-Path "C:\ProgramData\miniconda3\Scripts\conda.exe"){
	    Write-Host ($env:CONDA_PROMPT_MODIFIER.Trim()) -nonewline -foregroundcolor darkblue -BackgroundColor DarkYellow -ErrorAction SilentlyContinue
	}    

    if ($isAdmin) {
        Write-Host ("[" + (Get-Location) + "]") -nonewline -foregroundcolor black -BackgroundColor red 
        "# "
    }
    else {
        Write-Host ("[" + (Get-Location) + "]") -nonewline -foregroundcolor black -BackgroundColor Blue
        "$ "
    }
}

$Host.UI.RawUI.WindowTitle = "PowerShell {0}" -f $PSVersionTable.PSVersion.ToString()
if ($isAdmin) {
    $Host.UI.RawUI.WindowTitle += " [ADMIN]"
}

# Does the the rough equivalent of dir /s /b. For example, dirs *.png is dir /s /b *.png
function dirs {
    if ($args.Count -gt 0) {
        Get-ChildItem -Recurse -Include "$args" | Foreach-Object FullName
    }
    else {
        Get-ChildItem -Recurse | Foreach-Object FullName
    }
}

# Simple function to start a new elevated process. If arguments are supplied then 
# a single command is started with admin rights; if not then a new admin instance
# of PowerShell is started.
function admin {
    if ($args.Count -gt 0) {   
        $argList = "& '" + $args + "'"
        Start-Process "$psHome\pwsh.exe" -Verb runAs -ArgumentList $argList
    }
    else {
        Start-Process "$psHome\pwsh.exe" -Verb runAs
    }
}

# Set UNIX-like aliases for the admin command, so sudo <command> will run the command
# with elevated rights. 
Set-Alias -Name su -Value admin
Set-Alias -Name sudo -Value admin


# Make it easy to edit this profile once it's installed
function Edit-Profile {
    if ($host.Name -match "ise") {
        $psISE.CurrentPowerShellTab.Files.Add($profile.CurrentUserAllHosts)
    }
    else {
        notepad $profile
    }
}

function reload-profile {
    & $PROFILE
}

function upgrade-profile {
    Invoke-RestMethod https://github.com/dlsathvik04/PowerShell-Tweaks/raw/main/default.ps1 -OutFile $PROFILE
    Invoke-Command { & "pwsh.exe"} -NoNewScope
}

function uninstall-profile {
    rm $PROFILE
    Invoke-Command { & "pwsh.exe"} -NoNewScope
}

# We don't need these any more; they were just temporary variables to get to $isAdmin. 
# Delete them to prevent cluttering up the user profile. 
Remove-Variable identity
Remove-Variable principal



Set-Alias -Name vim -Value nvim
Set-Alias -Name gedit -Value notepad
Set-Alias -Name n -Value notepad

function ll { Get-ChildItem -Path $pwd -File }


function gcom {
    git add .
    git commit -m "$args"
}

function gpush {
    git add .
    git commit -m "$args"
    git push
}


function Get-PubIP {
    (Invoke-WebRequest http://ifconfig.me/ip ).Content
}

function find-file($name) {
    Get-ChildItem -recurse -filter "*${name}*" -ErrorAction SilentlyContinue | ForEach-Object {
        $place_path = $_.directory
        Write-Output "${place_path}\${_}"
    }
}
function unzip ($file) {
    Write-Output("Extracting", $file, "to", $pwd)
    $fullFile = Get-ChildItem -Path $pwd -Filter .\cove.zip | ForEach-Object { $_.FullName }
    Expand-Archive -Path $fullFile -DestinationPath $pwd
}
function ix ($file) {
    curl.exe -F "f:1=@$file" ix.io
}

Set-Alias -Name grep -Value findstr

function df {
    get-volume
}
function sed($file, $find, $replace) {
    (Get-Content $file).replace("$find", $replace) | Set-Content $file
}
function which($name) {
    Get-Command $name | Select-Object -ExpandProperty Definition
}
function export($name, $value) {
    set-item -force -path "env:$name" -value $value;
}


function export-global($name, $value) {
    if ($isAdmin) {
        [Environment]::SetEnvironmentVariable($name, $value, 'Machine')
    }
    else {
        [Environment]::SetEnvironmentVariable($name, $value, 'User')
    }
}


Set-Alias -Name pkill -Value Stop-Process
Set-Alias -Name touch -Value New-Item

function pgrep($name, $id, $search, $port) {
    if ($id) {
        Get-Process -Id $id 
    }
    elseif ($search) {
        Get-Process *$search*
    }
    elseif ($port) {
        Get-NetTCPConnection -LocalPort $port | Get-Process -Id { $_.OwningProcess }
    }
    else {
        if ($name){
            Get-Process $name 
        }else{
            Get-Process
        }
    }
}

function source($dir) {
    $Env:Path += ";$dir"
}

# Manage path here
# source <Path>
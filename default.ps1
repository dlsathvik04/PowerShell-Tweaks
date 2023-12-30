$version = "1.0.4"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Remove-Variable identity
Remove-Variable principal


# Conda Integration
If (Test-Path "C:\ProgramData\miniconda3\Scripts\conda.exe") {
    (& "C:\ProgramData\miniconda3\Scripts\conda.exe" "shell.powershell" "hook") | Out-String | ?{$_} | Invoke-Expression
}

Function Test-CommandExists {
    Param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    try { if (Get-Command $command) { RETURN $true } }
    Catch { Write-Host "$command does not exist"; RETURN $false }
    Finally { $ErrorActionPreference = $oldPreference }
}


# Editor Setup ---------------------------------------------------------------------------------
if (Test-CommandExists nvim) {
    $EDITORCL='nvim'
} elseif (Test-CommandExists pvim) {
    $EDITORCL='pvim'
} elseif (Test-CommandExists vim) {
    $EDITORCL='vim'
} elseif (Test-CommandExists vi) {
    $EDITORCL='vi'
} 

if (Test-CommandExists code) {
    $EDITOR='code'
} elseif (Test-CommandExists notepad) {
    $EDITOR='notepad++'
} elseif (Test-CommandExists notepad++) {
    $EDITOR='sublime_text'
} elseif (Test-CommandExists sublime_text) {
    $EDITOR='notepad'
}

if ($EDITORCL){
    Set-Alias -Name vim -Value $EDITORCL
}

Set-Alias -Name gedit -Value $EDITOR
Set-Alias -Name n -Value notepad



# Useful shortcuts for traversing directories---------------------------------------------------------------------
function cd... { Set-Location ..\.. }
function cd.... { Set-Location ..\..\.. }
function exp { explorer.exe . }

# Compute file hashes - useful for checking successful downloads -------------------------------------------------
function md5 { Get-FileHash -Algorithm MD5 $args }
function sha1 { Get-FileHash -Algorithm SHA1 $args }
function sha256 { Get-FileHash -Algorithm SHA256 $args }


# Drive shortcuts ------------------------------------------------------------------------------------------------
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

# Setup Prompt Style ------------------------------------------------------------------------------------------------
function prompt { 
    if (Test-Path .git) {
        git branch | ForEach-Object {
            if ($_ -match "^\*(.*)") {
                Write-Host ("(" + $matches[1].Trim() + ")") -nonewline -foregroundcolor white -BackgroundColor red
            }
        }
    }
    
    if (Test-CommandExists){
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

# Setup Window title ------------------------------------------------------------------------------------------------
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
# Set UNIX-like aliases for the admin command, so sudo <command> will run the command
# with elevated rights. 
function admin {
    if ($args.Count -gt 0) {   
        $argList = "& '" + $args + "'"
        Start-Process "$psHome\pwsh.exe" -Verb runAs -ArgumentList $argList
    }
    else {
        Start-Process "$psHome\pwsh.exe" -Verb runAs
    }
}

Set-Alias -Name su -Value admin
Set-Alias -Name sudo -Value admin

# Proflie Utils -------------------------------------------------------------------------------------------------------------
# Retrieve profile version
function profile-version{
    Write-host "Powershell Tweaks Version " + $version
    Write-host "Licenced under The UNLICENSE."
    Write-host "This is free and unencumbered software released into the public domain."
}
# Make it easy to edit this profile once it's installed
function Edit-Profile {
    if ($host.Name -match "ise") {
        $psISE.CurrentPowerShellTab.Files.Add($profile.CurrentUserAllHosts)
    }
    else {
        gedit $profile
    }
}

function reload-profile {
    & $PROFILE
}

function upgrade-profile {
    $Message = "The upgrade overrrides the profile with the latest version in web. All the changes you made locally will be lost are you sure you want to continue?"
    do {
        Write-Host $Message -ForegroundColor Yellow
        $response = Read-Host "Press 'Y' to continue or any other key to exit: "

        if ($response -ne 'Y') {
            Write-Host "Execution stopped." -ForegroundColor Red
            return  # Exit the function if input is not 'Y'
        }
    } while ($response -ne 'Y')

    Write-Host "Updating the profile..."
    Invoke-RestMethod https://github.com/dlsathvik04/PowerShell-Tweaks/raw/main/default.ps1 -OutFile $PROFILE
    Invoke-Command { & "pwsh.exe"} -NoNewScope
}

function uninstall-profile {
    rm $PROFILE
    Invoke-Command { & "pwsh.exe"} -NoNewScope
}

# We don't need these any more; they were just temporary variables to get to $isAdmin. 
# Delete them to prevent cluttering up the user profile. 


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


# C and Cpp Utils -----------------------------------------------------------------------------------------------------
function run{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $path,

        [Parameter()]
        [switch] $c,

        [Parameter()]
        [switch] $cpp,

        [Parameter()]
        [switch] $t
    )

    if ($c) {
        gcc $path -o runc.exe
        .\runc.exe

    } elseif($cpp){
        g++ $path -o runc.exe
        .\runc.exe
    }
    else {
        Write-Host "No Compiler specified"
    }
    if ($t){
        rm .\runc.exe
    }
}

if (Test-CommandExists mingw32-make){
    Set-Alias -Name make -Value mingw32-make
}




# Manage path here
# source <Path>
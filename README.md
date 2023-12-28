# PowerShell-Tweaks

A PowerShell customization repository built based on <a href = "https://github.com/ChrisTitusTech/powershell-profile/"> this </a> repo by ChrisTitusTech with simplicity and light-weight in mind.

![Alt text](image.png)
![Alt text](image-1.png)

# Installation

Make sure you have Powershell 7 or above installed already, if not, use the command:
```
winget install --id Microsoft.Powershell
```
Windows has it's powershell execution policy set to restricted which does not allow execution of powershell scripts. Use the command in an administrator Powershell
```
Set-ExecutionPolicy Remotesigned
```
Now, to install the 'tweak':

```
irm https://github.com/dlsathvik04/PowerShell-Tweaks/raw/main/install.ps1 | iex
```

**Conda integration only works when conda is configured for powershell and is in path**

# Functionality and Reference

## Added Aliases

gedit, n -> notepad

vim -> nvim (if you have nvim installed)

pkill -> Stop-Process

touch -> New-Item

## Added functions

### cd... and cd.... :

works similar to
`cd ..\.. `
and
`cd ..\..\..`

### md5, sha1, sha256 :

works based on the `Get-FileHash` commandlet with tags `MD5, SHA1, SHA256`

### exp :

opens explorer in the current directory

### dirs :

Does the the rough equivalent of dir /s /b. For example, dirs _.png is dir /s /b _.png

### admin (su, sudo):

Simple function to start a new elevated process. If arguments are supplied then a single command is started with admin rights; if not then a new admin instance of PowerShell is started.

### gcom and gpush:

A lazy git shortcut which executes the following code

```
function gcom {
    git add .
    git commit -m "$args"
}
```

```
function gpush {
    git add .
    git commit -m "$args"
    git push
}
```

## Uninstall the profile
To switch back to the default powershell profile(clean) use the command in powershell:
```
uninstall-profile
```

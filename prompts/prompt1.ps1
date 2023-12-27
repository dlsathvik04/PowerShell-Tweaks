
function prompt { 
    if (Test-Path .git) {
        git branch | ForEach-Object {
            if ($_ -match "^\*(.*)") {
                Write-Host ("(" + $matches[1].Trim() + ")") -nonewline -foregroundcolor white -BackgroundColor red
            }
        }
    }
    
    Write-Host ($env:CONDA_PROMPT_MODIFIER.Trim()) -nonewline -foregroundcolor darkblue -BackgroundColor DarkYellow
    
    if ($isAdmin) {
        Write-Host ("[" + (Get-Location) + "]") -nonewline -foregroundcolor black -BackgroundColor red 
        "# "
    }
    else {
        Write-Host ("[" + (Get-Location) + "]") -nonewline -foregroundcolor black -BackgroundColor Blue
        "$ "
    }
}
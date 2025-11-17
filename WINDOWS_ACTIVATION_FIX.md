# Windows Virtual Environment Activation Fix

## Problem
The command `.venv\Scripts\activate` doesn't work in PowerShell due to execution policy restrictions.

## Solutions

### Option 1: Use activate.bat (Recommended - Works Everywhere)
```powershell
.venv\Scripts\activate.bat
```

This works in both PowerShell and CMD and bypasses execution policy issues.

### Option 2: Use the Full Path to activate.bat
```powershell
& .\.venv\Scripts\activate.bat
```

### Option 3: Bypass Execution Policy for One Script (PowerShell Only)
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.venv\Scripts\Activate.ps1
```

### Option 4: Use CMD Instead of PowerShell
Open Command Prompt (cmd.exe) instead of PowerShell and use:
```cmd
.venv\Scripts\activate.bat
```

## Recommended Approach
Simply use `.venv\Scripts\activate.bat` - it works reliably in both PowerShell and CMD without any policy changes.

## Verification
After activation, you should see `(.venv)` at the beginning of your command prompt:
```
(.venv) PS C:\Users\pc\Downloads\saadahmed1084-securechat (1)\securechat-skeleton-main>
```


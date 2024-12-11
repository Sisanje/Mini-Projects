# This script will create and enable both of the required registry keys to abuse the AlwaysInstallElevated feature

Write-Host "[*] Checking if current PowerShell session is running with high privileges...`n"

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )

if ($currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator ))
    {
        Write-host "[+] PowerShell running as administrator!`n"
        
        
        Write-Host "[+] Configuring HKEY_LOCAL_MACHINE registry`n"
        # Creating new key and adding value to in in HKLM
        New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name Installer -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 1

        Write-Host "`n[+] Configuring HKEY_CURRENT_USER registry`n"
        # Creating new key and adding value to in in HKLM
        New-Item -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows -Name Installer -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 1

    }
else
    {
        Write-Host "[-] PowerShell must be running as administrator!`n"
    }

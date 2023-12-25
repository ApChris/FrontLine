$banner = @"


   ███████╗██████╗  ██████╗ ███╗   ██╗████████╗██╗     ██╗███╗   ██╗███████╗
   ██╔════╝██╔══██╗██╔═══██╗████╗  ██║╚══██╔══╝██║     ██║████╗  ██║██╔════╝
   █████╗  ██████╔╝██║   ██║██╔██╗ ██║   ██║   ██║     ██║██╔██╗ ██║█████╗  
   ██╔══╝  ██╔══██╗██║   ██║██║╚██╗██║   ██║   ██║     ██║██║╚██╗██║██╔══╝  
   ██║     ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║██║ ╚████║███████╗
   ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝╚═╝  ╚═══╝╚══════╝
                                                                    
                    Author: Christoforos Apostolopoulos
                    GitHub: https://github.com/ApChris
                    License: GNU General Public License v3.0


"@

Write-Host $banner

function Test-AdminPrivileges 
{
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator

    return $currentUser.IsInRole($adminRole)
}

function Create-OutputFolder 
{
    param ([string]$scriptFolder)

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $rootFolder = Join-Path -Path $scriptFolder -ChildPath "FrontLine\$timestamp"
    New-Item -ItemType Directory -Path $rootFolder -Force | Out-Null

    return $rootFolder
}

function Save-InfoToFile 
{
    param ([string]$outputFolder,[string]$category,[object]$data)

    $filePath = Join-Path -Path $outputFolder -ChildPath "$category.txt"
    $data | Out-File -FilePath $filePath -Append
}

function Get-DNSCacheConfig 
{
    $dnsCacheConfig = ipconfig /displaydns
    Save-InfoToFile -outputFolder $outputFolder -category "DNSCacheConfig" -data $dnsCacheConfig
}

function Get-ARPDetailed 
{
    $arpTable = arp -a
    Save-InfoToFile -outputFolder $outputFolder -category "ARPDetailed" -data $arpTable
}

function Get-InstalledSoftware 
{
    $registryPaths = @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')

    $installedSoftware = $registryPaths | ForEach-Object 
    {
        Get-Item -LiteralPath $_ -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object { $_.DisplayName -and $_.DisplayVersion } | Select-Object DisplayName, DisplayVersion, Publisher
    }

    Save-InfoToFile -outputFolder $outputFolder -category "InstalledSoftware" -data $installedSoftware | Format-Table -AutoSize
}

function Get-AntivirusLogs 
{
    # $antivirusLogs = Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -FilterXPath "*[System[EventID=1116 or EventID=1121]]" -ErrorAction SilentlyContinue
    $antivirusLogs = Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -ErrorAction SilentlyContinue
    if ($antivirusLogs) 
    {
        Save-InfoToFile -outputFolder $outputFolder -category "AntivirusLogs" -data $antivirusLogs | Format-Table -AutoSize
    } 
    else 
    {
        Save-InfoToFile -outputFolder $outputFolder -category "AntivirusLogs" -data "No antivirus logs found."
    }
}

function Get-FirewallLogs 
{
    $firewallLogs = Get-WinEvent -LogName 'Security' -FilterXPath "*[System[EventID=5152 or EventID=5153]]" -ErrorAction SilentlyContinue

    if ($firewallLogs) 
    {
        Save-InfoToFile -outputFolder $outputFolder -category "FirewallLogs" -data $firewallLogs | Format-Table -AutoSize
    } 
    else 
    {
        Save-InfoToFile -outputFolder $outputFolder -category "FirewallLogs" -data "No firewall logs found in Security log. Checking Microsoft-Windows-Windows Firewall With Advanced Security/Firewall log."

        $firewallLogs = Get-WinEvent -LogName 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' -FilterXPath "*[System[EventID=2003 or EventID=2004]]" -ErrorAction SilentlyContinue

        if ($firewallLogs) 
        {
            Save-InfoToFile -outputFolder $outputFolder -category "FirewallLogs" -data $firewallLogs | Format-Table -AutoSize
        } 
        else 
        {
            Save-InfoToFile -outputFolder $outputFolder -category "FirewallLogs" -data "No firewall logs found in Security or Microsoft-Windows-Windows Firewall With Advanced Security/Firewall logs."
        }
    }
}

function Get-DNSCache
{
    $dnsCache = ipconfig /displaydns
    Save-InfoToFile -outputFolder $outputFolder -category "DNSCache" -data $dnsCache
}

function Get-ARP 
{
    $arpTable = arp -a
    Save-InfoToFile -outputFolder $outputFolder -category "ARP" -data $arpTable
}

function Get-ExtensionDetails 
{
    param ([string]$browserName,[string]$extensionsPath)

    $browserExtensionsPath = Join-Path -Path $env:LOCALAPPDATA -ChildPath $extensionsPath
    if (Test-Path $browserExtensionsPath) 
    {
        $browserExtensions = Get-ChildItem -Path $browserExtensionsPath -Directory
        $extensionDetails = foreach ($extension in $browserExtensions) 
        {
            $manifestPath = Get-ChildItem -Path $extension.FullName -Filter 'manifest.json' -Recurse -File | Select-Object -First 1 -ExpandProperty FullName
            if ($manifestPath) 
            {
                try 
                {
                    $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
                    $extensionName = $manifest.name
                }
                catch 
                {
                    $extensionName = "Unknown"
                }
            }
            else 
            {
                $extensionName = "Unknown"
            }

            [PSCustomObject]@{
                Name = $extensionName
                ID = $extension.Name
                Path = $extension.FullName
            }
        }

        Save-InfoToFile -outputFolder $outputFolder -category "${browserName}Extensions" -data $extensionDetails | Format-Table -AutoSize
    }
    else 
    {
        Save-InfoToFile -outputFolder $outputFolder -category "${browserName}Extensions" -data "Extensions folder not found for $browserName."
    }
}



if (Test-AdminPrivileges) 
{
    $scriptFolder = Split-Path -Parent $MyInvocation.MyCommand.Path

    $outputFolder = Create-OutputFolder -scriptFolder $scriptFolder

    Save-InfoToFile -outputFolder $outputFolder -category "SystemInfo" -data (Get-ComputerInfo | Format-List)
    Save-InfoToFile -outputFolder $outputFolder -category "RunningProcesses" -data (Get-Process | Format-Table -AutoSize)
    Save-InfoToFile -outputFolder $outputFolder -category "UserInfo" -data "Current User: $(whoami)"
    Save-InfoToFile -outputFolder $outputFolder -category "NetworkInfo" -data (ipconfig /all)
    Save-InfoToFile -outputFolder $outputFolder -category "EnvironmentVariables" -data (Get-ChildItem Env: | Format-Table -AutoSize)

    try 
    {
        $events4624 = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -ErrorAction Stop
        Save-InfoToFile -outputFolder $outputFolder -category "RecentLogins" -data ($events4624 | Format-Table -AutoSize)
    }
    catch 
    {
        Save-InfoToFile -outputFolder $outputFolder -category "RecentLogins" -data "No recent login events found."
    }

    try 
    {
        $events4625 = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -ErrorAction Stop
        Save-InfoToFile -outputFolder $outputFolder -category "FailedLogins" -data ($events4625 | Format-Table -AutoSize)
    }
    catch 
    {
        Save-InfoToFile -outputFolder $outputFolder -category "FailedLogins" -data "No failed login events found."
    }

    $outputFilePathSecurity = Join-Path -Path $outputFolder -ChildPath "SecurityLogs.txt"
    Get-WinEvent -LogName Security | ForEach-Object { "$($_.Id): $($_.Message)" } | Out-File -FilePath $outputFilePathSecurity

    Save-InfoToFile -outputFolder $outputFolder -category "Autoruns" -data (Get-CimInstance -ClassName Win32_StartupCommand | Format-Table -AutoSize)
    Save-InfoToFile -outputFolder $outputFolder -category "Services" -data (Get-Service | Format-Table -AutoSize)
    Save-InfoToFile -outputFolder $outputFolder -category "Administrators" -data (Get-LocalGroupMember -Group "Administrators" | Format-Table -AutoSize)
    Save-InfoToFile -outputFolder $outputFolder -category "SMBSessions" -data (Get-SmbSession | Format-Table -AutoSize)
    Save-InfoToFile -outputFolder $outputFolder -category "OpenPorts" -data (Get-NetTCPConnection | Format-Table -AutoSize)
    Save-InfoToFile -outputFolder $outputFolder -category "ActiveSessions" -data (Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' } | Format-Table -AutoSize)
    Save-InfoToFile -outputFolder $outputFolder -category "InstalledPrinters" -data (Get-Printer | Format-Table -AutoSize)
    Save-InfoToFile -outputFolder $outputFolder -category "TempFiles" -data (Get-ChildItem -Path "$env:TEMP" -Recurse | Format-Table -AutoSize)
    Save-InfoToFile -outputFolder $outputFolder -category "DownloadedFiles" -data (Get-ChildItem -Path "$env:USERPROFILE\Downloads" -Recurse | Format-Table -AutoSize)

    Get-DNSCache
    Get-ARP

    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Select-Object DisplayName, DisplayVersion, Publisher, Size, InstallDate | Format-Table -AutoSize | Out-String | Out-File -FilePath (Join-Path -Path $outputFolder -ChildPath "InstalledSoftware.txt")
    
    Get-AntivirusLogs    
    Get-FirewallLogs

    Get-ExtensionDetails -browserName "Edge" -extensionsPath "Microsoft\Edge\User Data\Default\Extensions"
    Get-ExtensionDetails -browserName "Chrome" -extensionsPath "Google\Chrome\User Data\Default\Extensions"
    Get-ExtensionDetails -browserName "Firefox" -extensionsPath "Mozilla\Firefox\Profiles"

    Write-Host "Information collected and saved to: $outputFolder"
} 
else 
{
    Write-Host "Please run the script with elevated privileges (Run as Administrator)."
}

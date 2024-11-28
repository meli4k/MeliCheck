Clear-Host

$headerBase64 = "ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAg4paI4paI4paI4paEIOKWhOKWiOKWiOKWiOKWk+KWk+KWiOKWiOKWiOKWiOKWiCAg4paI4paI4paTICAgICDilojilojilpMgICAg4paE4paI4paI4paI4paI4paEICAg4paI4paI4paRIOKWiOKWiCDilpPilojilojilojilojiloggIOKWhOKWiOKWiOKWiOKWiOKWhCAgIOKWiOKWiCDiloTilojiloAKICAgICAgICAgICAgICAgICAgICDilpPilojilojilpLiloDilojiloAg4paI4paI4paS4paT4paIICAg4paAIOKWk+KWiOKWiOKWkiAgICDilpPilojilojilpIgICDilpLilojilojiloAg4paA4paIICDilpPilojilojilpEg4paI4paI4paS4paT4paIICAg4paAIOKWkuKWiOKWiOKWgCDiloDiloggICDilojilojiloTilojilpIKICAgICAgICAgICAgICAgICAgICDilpPilojiloggICAg4paT4paI4paI4paR4paS4paI4paI4paIICAg4paS4paI4paI4paRICAgIOKWkuKWiOKWiOKWkiAgIOKWkuKWk+KWiCAgICDiloQg4paS4paI4paI4paA4paA4paI4paI4paR4paS4paI4paI4paIICAg4paS4paT4paIICAgIOKWhCDilpPilojilojilojiloTilpEKICAgICAgICAgICAgICAgICAgICDilpLilojiloggICAg4paS4paI4paIIOKWkuKWk+KWiCAg4paEIOKWkuKWiOKWiOKWkSAgICDilpHilojilojilpEgICDilpLilpPilpPiloQg4paE4paI4paI4paS4paR4paT4paIIOKWkeKWiOKWiCDilpLilpPiloggIOKWhCDilpLilpPilpPiloQg4paE4paI4paI4paS4paT4paI4paIIOKWiOKWhAogICAgICAgICAgICAgICAgICAgIOKWkuKWiOKWiOKWkiAgIOKWkeKWiOKWiOKWkuKWkeKWkuKWiOKWiOKWiOKWiOKWkuKWkeKWiOKWiOKWiOKWiOKWiOKWiOKWkuKWkeKWiOKWiOKWkSAgIOKWkiDilpPilojilojilojiloAg4paR4paR4paT4paI4paS4paR4paI4paI4paT4paR4paS4paI4paI4paI4paI4paS4paSIOKWk+KWiOKWiOKWiOKWgCDilpHilpLilojilojilpIg4paI4paECiAgICAgICAgICAgICAgICAgICAg4paRIOKWkuKWkSAgIOKWkSAg4paR4paR4paRIOKWkuKWkSDilpHilpEg4paS4paR4paTICDilpHilpHilpMgICAgIOKWkSDilpHilpIg4paSICDilpEg4paSIOKWkeKWkeKWkuKWkeKWkuKWkeKWkSDilpLilpEg4paR4paRIOKWkeKWkiDilpIgIOKWkeKWkiDilpLilpIg4paT4paSCiAgICAgICAgICAgICAgICAgICAg4paRICDilpEgICAgICDilpEg4paRIOKWkSAg4paR4paRIOKWkSDilpIgIOKWkSDilpIg4paRICAgICDilpEgIOKWkiAgICDilpIg4paR4paS4paRIOKWkSDilpEg4paRICDilpEgIOKWkSAg4paSICAg4paRIOKWkeKWkiDilpLilpEKICAgICAgICAgICAgICAgICAgICDilpEgICAgICDilpEgICAgICDilpEgICAgIOKWkSDilpEgICAg4paSIOKWkSAgIOKWkSAgICAgICAgIOKWkSAg4paR4paRIOKWkSAgIOKWkSAgIOKWkSAgICAgICAg4paRIOKWkeKWkSDilpEgCiAgICAgICAgICAgICAgICAgICAgICAgICAg4paRICAgICAg4paRICDilpEgICAg4paRICDilpEg4paRICAgICDilpEg4paRICAgICAgIOKWkSAg4paRICDilpEgICDilpEgIOKWkeKWkSDilpEgICAgICDilpEgIOKWkSAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg4paRICAgICAgICAgICAgICAgICAgICAgICDilpEgICAgICAgICAgICAg"
$headerString = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($headerBase64))
$headerLines = $headerString -split "`n"

foreach ($line in $headerLines) {
    Write-Host $line -ForegroundColor DarkRed
    Start-Sleep -Milliseconds 200
}
Start-Sleep -Seconds 2

Write-Host ""
Write-Host ""

$name = Read-Host -Prompt "Type your name here"
$logFileName = "$name`_Log.txt"

Clear-Host

Write-Host "Hello, $name! The script is now starting..." -ForegroundColor Green

function Get-OneDrivePath {
    $oneDrivePath = (Get-ItemProperty "HKCU:\Software\Microsoft\OneDrive" -Name "UserFolder" -ErrorAction SilentlyContinue).UserFolder
    if (-not $oneDrivePath) {
        Write-Warning "OneDrive path not found in registry. Attempting alternative detection..."
        $envOneDrive = [System.IO.Path]::Combine($env:UserProfile, "OneDrive")
        if (Test-Path $envOneDrive) {
            $oneDrivePath = $envOneDrive
            Write-Host "OneDrive path detected using environment variable: $oneDrivePath" -ForegroundColor Green
        } else {
            Write-Error "Unable to find OneDrive path automatically."
            return $null
        }
    }

    return $oneDrivePath
}
$oneDrivePath = Get-OneDrivePath
if ($oneDrivePath) {
    Write-Host "OneDrive path: $oneDrivePath"
} else {
    Write-Host "OneDrive path could not be determined."
}

function Format-Output {
    param($name, $value)
    "{0} : {1}" -f $name, $value -replace 'System.Byte\[\]', ''
}

function Log-FolderNames {
    $userName = $env:UserName
    $oneDrivePath = Get-OneDrivePath
    $potentialPaths = @("C:\Users\$userName\Documents\My Games\Rainbow Six - Siege","$oneDrivePath\Documents\My Games\Rainbow Six - Siege")
    $allUserNames = @()

    foreach ($path in $potentialPaths) {
        if (Test-Path -Path $path) {
            $dirNames = Get-ChildItem -Path $path -Directory | ForEach-Object { $_.Name }
            $allUserNames += $dirNames
        }
    }

    $uniqueUserNames = $allUserNames | Select-Object -Unique

    if ($uniqueUserNames.Count -eq 0) {
        Write-Output "R6 directory not found."
    } else {
        return $uniqueUserNames
    }
}

function Find-RarAndExeFiles {
    Write-Output "Finding .rar and .exe files..."
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')
    $outputFile = Join-Path -Path $desktopPath -ChildPath $logFileName
    $oneDriveFileHeader = "`n-----------------`nOneDrive Files:`n"
    $oneDriveFiles = [System.Collections.Generic.List[string]]::new()
    $allFiles = [System.Collections.Generic.List[string]]::new()
    $rarSearchPaths = Get-PSDrive -PSProvider 'FileSystem' | ForEach-Object { $_.Root }
    $oneDrivePath = Get-OneDrivePath
    if ($oneDrivePath) { $rarSearchPaths += $oneDrivePath }
    $searchFiles = {
        param ($path, $filter, $oneDriveFiles, $allFiles)
        Get-ChildItem -Path $path -Recurse -Filter $filter -ErrorAction SilentlyContinue | ForEach-Object {
            $allFiles.Add($_.FullName)
            if ($_.FullName -like "*OneDrive*") { $oneDriveFiles.Add($_.FullName) }
        }
    }
    $rarJob = Start-Job -ScriptBlock $searchFiles -ArgumentList $rarSearchPaths, "*.rar", $oneDriveFiles, $allFiles
    if ($oneDrivePath) {
        $exeJob = Start-Job -ScriptBlock $searchFiles -ArgumentList @($oneDrivePath), "*.exe", $oneDriveFiles, $allFiles
    }
    $rarJob | Wait-Job
    if ($exeJob) { $exeJob | Wait-Job }
    $rarResults = Receive-Job -Job $rarJob
    $exeResults = if ($exeJob) { Receive-Job -Job $exeJob } else { @() }
    Remove-Job -Job $rarJob
    if ($exeJob) { Remove-Job -Job $exeJob }
    $allFiles = $rarResults + $exeResults | Sort-Object
    if ($oneDriveFiles.Count -gt 0) {
        Add-Content -Path $outputFile -Value $oneDriveFileHeader
        $oneDriveFiles | Sort-Object | ForEach-Object { Add-Content -Path $outputFile -Value $_ }
    }
    $allFiles | ForEach-Object { Add-Content -Path $outputFile -Value $_ }
}

function Find-SusFiles {
    Write-Output "Finding suspicious file names..."
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')
    $outputFile = Join-Path -Path $desktopPath -ChildPath $logFileName
    $susFilesHeader = "`n-----------------`nSus Files:`n"
    $susFiles = @()
    if (Test-Path $outputFile) {
        $loggedFiles = Get-Content -Path $outputFile
        foreach ($file in $loggedFiles) {
            if ($file -match "loader.*\.exe" -or $file -match "client.*\.exe" -or $file -match "Chlorine.*\.exe") {
                $susFiles += $file
            }
        }
        if ($susFiles.Count -gt 0) {
            Add-Content -Path $outputFile -Value $susFilesHeader
            $susFiles | Sort-Object | ForEach-Object { Add-Content -Path $outputFile -Value $_ }
            Write-Output "Suspicious files logged in $logFileName."
        } else {
            Write-Output "No suspicious files found."
        }
    } else {
        Write-Output "Log file not found. Unable to search for suspicious files."
    }
}

function List-BAMStateUserSettings {
    Write-Host "Logging reg entries inside PowerShell..." -ForegroundColor DarkYellow
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')
    $outputFile = Join-Path -Path $desktopPath -ChildPath $logFileName
    if (Test-Path $outputFile) { Clear-Content $outputFile }
    $loggedPaths = @{}
     Write-Host " Fetching UserSettings Entries " -ForegroundColor Blue
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
    $userSettings = Get-ChildItem -Path $registryPath | Where-Object { $_.Name -like "*1001" }

    if ($userSettings) {
        foreach ($setting in $userSettings) {
            Add-Content -Path $outputFile -Value "`n$($setting.PSPath)"
            $items = Get-ItemProperty -Path $setting.PSPath | Select-Object -Property *
            foreach ($item in $items.PSObject.Properties) {
                if (($item.Name -match "exe" -or $item.Name -match ".rar") -and -not $loggedPaths.ContainsKey($item.Name)) {
                    Add-Content -Path $outputFile -Value (Format-Output $item.Name $item.Value)
                    $loggedPaths[$item.Name] = $true
                }
            }
        }
    } else {
        Write-Host "No relevant user settings found." -ForegroundColor Red
    }
Write-Host "Fetching Compatibility Assistant Entries"
    $compatRegistryPath = "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"
    $compatEntries = Get-ItemProperty -Path $compatRegistryPath
    $compatEntries.PSObject.Properties | ForEach-Object {
        if (($_.Name -match "exe" -or $_.Name -match ".rar") -and -not $loggedPaths.ContainsKey($_.Name)) {
            Add-Content -Path $outputFile -Value (Format-Output $_.Name $_.Value)
            $loggedPaths[$_.Name] = $true
        }
    }
Write-Host "Fetching AppsSwitched Entries" -ForegroundColor Blue
    $newRegistryPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched"
    if (Test-Path $newRegistryPath) {
        $newEntries = Get-ItemProperty -Path $newRegistryPath
        $newEntries.PSObject.Properties | ForEach-Object {
            if (($_.Name -match "exe" -or $_.Name -match ".rar") -and -not $loggedPaths.ContainsKey($_.Name)) {
                Add-Content -Path $outputFile -Value (Format-Output $_.Name $_.Value)
                $loggedPaths[$_.Name] = $true
            }
        }
    }
Write-Host "Fetching MuiCache Entries" -ForegroundColor Blue
    $muiCachePath = "HKCR:\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
    if (Test-Path $muiCachePath) {
        $muiCacheEntries = Get-ChildItem -Path $muiCachePath
        $muiCacheEntries.PSObject.Properties | ForEach-Object {
            if (($_.Name -match "exe" -or $_.Name -match ".rar") -and -not $loggedPaths.ContainsKey($_.Name)) {
                Add-Content -Path $outputFile -Value (Format-Output $_.Name $_.Value)
                $loggedPaths[$_.Name] = $true
            }
        }
    }

    Get-Content $outputFile | Sort-Object | Get-Unique | Where-Object { $_ -notmatch "\{.*\}" } | ForEach-Object { $_ -replace ":", "" } | Set-Content $outputFile

    Log-BrowserFolders
  
    $folderNames = Log-FolderNames | Sort-Object | Get-Unique
    Add-Content -Path $outputFile -Value "`n-----------------"
    Add-Content -Path $outputFile -Value "`nR6 Usernames:"

    foreach ($name in $folderNames) {
        Add-Content -Path $outputFile -Value $name
        $url = "https://stats.cc/siege/$name"
        Write-Host "Opening stats for $name on Stats.cc ..." -ForegroundColor Blue
        Start-Process $url
        Start-Sleep -Seconds 0.5
    }
}
Write-Host " Fetching Downloaded Browsers " -ForegroundColor Blue
function Log-BrowserFolders {
    Write-Host "Logging reg entries inside PowerShell..." -ForegroundColor DarkYellow
    $registryPath = "HKLM:\SOFTWARE\Clients\StartMenuInternet"
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')
    $outputFile = Join-Path -Path $desktopPath -ChildPath $logFileName
    if (Test-Path $registryPath) {
        $browserFolders = Get-ChildItem -Path $registryPath
        Add-Content -Path $outputFile -Value "`n-----------------"
        Add-Content -Path $outputFile -Value "`nBrowser Folders:"
        foreach ($folder in $browserFolders) { Add-Content -Path $outputFile -Value $folder.Name }
    } else {
        Write-Host "Registry path for browsers not found." -ForegroundColor Red
    }
}

function Log-WindowsInstallDate {
    Write-Host "Logging Windows install date..." -ForegroundColor DarkYellow
    $os = Get-WmiObject -Class Win32_OperatingSystem
    $installDate = $os.ConvertToDateTime($os.InstallDate)
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')
    $outputFile = Join-Path -Path $desktopPath -ChildPath $logFileName
    Add-Content -Path $outputFile -Value "`n-----------------"
    Add-Content -Path $outputFile -Value "`nWindows Installation Date: $installDate"
}

function Search-PrefetchFiles {
    $prefetchFolderPath = "$env:SystemRoot\Prefetch"
    $outputFile = Join-Path -Path ([System.Environment]::GetFolderPath('Desktop')) -ChildPath $logFileName
    $prefetchHeader = "`n-----------------`nPrefetch Files:`n"
    if (Test-Path $prefetchFolderPath) {
        $prefetchFiles = Get-ChildItem -Path $prefetchFolderPath -Filter "*.pf" | ForEach-Object {
            "{0} - Last Accessed: {1}" -f $_.Name, $_.LastAccessTime
        }
        if ($prefetchFiles.Count -gt 0) {
            Add-Content -Path $outputFile -Value $prefetchHeader
            $prefetchFiles | ForEach-Object { Add-Content -Path $outputFile -Value $_ }
            Write-Host "Prefetch file information saved to $outputFile" -ForegroundColor Green
        } else {
            Write-Host "No prefetch files found."
        }
    } else {
        Write-Host "Prefetch folder not found."
    }
}

function Log-LogitechScripts {
    Write-Host "Logging Logitech scripts..." -ForegroundColor DarkYellow
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')
    $outputFile = Join-Path -Path $desktopPath -ChildPath $logFileName
    $logitechScriptsHeader = "`n-----------------`nLogitech Scripts:`n"
    Add-Content -Path $outputFile -Value $logitechScriptsHeader
    $scriptsPath = Join-Path -Path $env:LocalAppData -ChildPath "LGHUB\scripts"
    
    if (Test-Path -Path $scriptsPath) {
        try {
            $scriptFiles = Get-ChildItem -Path $scriptsPath -Recurse -File -ErrorAction SilentlyContinue

            if ($scriptFiles -and $scriptFiles.Count -gt 0) {
                foreach ($file in $scriptFiles) {
                    Add-Content -Path $outputFile -Value ("{0} - Last Modified: {1}" -f $file.FullName, $file.LastWriteTime)
                }
            } else {
                Add-Content -Path $outputFile -Value "No script files found."
            }
        } catch {
            Write-Host "Could not retrieve Logitech scripts." -ForegroundColor Red
            Add-Content -Path $outputFile -Value "Logitech Scripts: Retrieval failed."
        }
    } else {
        Write-Host "Logitech scripts directory not found." -ForegroundColor Red
        Add-Content -Path $outputFile -Value "Logitech Scripts: Directory not found."
    }

    Write-Host "Logitech scripts in $logFileName" -ForegroundColor Green
}

function Log-WindowsSecurityStatus {
    Write-Host "Logging Windows Security status..." -ForegroundColor DarkYellow
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')
    $outputFile = Join-Path -Path $desktopPath -ChildPath $logFileName
    $securityHeader = "`n-----------------`nWindows Security Status:`n"
    Add-Content -Path $outputFile -Value $securityHeader
    $antivirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue | Where-Object { $_.displayName -ne "Windows Defender" }

    if ($antivirusProducts) {
        Add-Content -Path $outputFile -Value "Third-Party Antivirus Software Detected:"
        foreach ($product in $antivirusProducts) {
            Add-Content -Path $outputFile -Value ("Name: {0}, State: {1}" -f $product.displayName, $product.productState)
        }
        Write-Host "Third-party antivirus software in $logFileName" -ForegroundColor Green
    } else {
        Write-Host "No third-party antivirus software found. Logging Windows Defender status..." -ForegroundColor Yellow
        try {
            $securityStatus = Get-MpComputerStatus
            Add-Content -Path $outputFile -Value ("Antivirus Enabled: {0}" -f (if ($securityStatus.AntivirusEnabled) { "Enabled" } else { "Disabled" }))
            Add-Content -Path $outputFile -Value ("Real-Time Protection Enabled: {0}" -f (if ($securityStatus.RealTimeProtectionEnabled) { "Enabled" } else { "Disabled" }))
            Add-Content -Path $outputFile -Value ("Firewall Enabled: {0}" -f (if ($securityStatus.FirewallEnabled) { "Enabled" } else { "Disabled" }))
            Add-Content -Path $outputFile -Value ("Antispyware Enabled: {0}" -f (if ($securityStatus.AntispywareEnabled) { "Enabled" } else { "Disabled" }))
            Add-Content -Path $outputFile -Value ("AMService Enabled: {0}" -f (if ($securityStatus.AMServiceEnabled) { "Enabled" } else { "Disabled" }))
            Add-Content -Path $outputFile -Value ("Quick Scan Age (Days): {0}" -f $securityStatus.QuickScanAge)
            Add-Content -Path $outputFile -Value ("Full Scan Age (Days): {0}" -f $securityStatus.FullScanAge)

            Write-Host "Windows Defender status logged in $logFileName" -ForegroundColor Green
        } catch {
            Write-Host "Failed to retrieve Windows Defender status via Get-MpComputerStatus. Checking alternative method..." -ForegroundColor Yellow
            Add-Content -Path $outputFile -Value "Failed to retrieve Windows Defender status via primary method."
            $defenderService = Get-WmiObject -Namespace "root\Microsoft\Windows\Defender" -Class MSFT_MpPreference -ErrorAction SilentlyContinue
            if ($defenderService) {
                $realtimeProtectionStatus = if ($defenderService.DisableRealtimeMonitoring -eq $false) { "Enabled" } else { "Disabled" }
                $cloudProtectionStatus = if ($defenderService.DisableIOAVProtection -eq $false) { "Enabled" } else { "Disabled" }
                $puaProtectionStatus = if ($defenderService.PUAProtection -eq 1) { "Enabled" } else { "Disabled" }
                $submissionConsent = switch ($defenderService.SubmissionConsent) {
                    0 { "Prompt before sending samples" }
                    1 { "Never send samples" }
                    2 { "Send safe samples automatically, prompt for sensitive ones" }
                    3 { "Always send all samples automatically" }
                    default { "Unknown" }
                }

                $scanAvgCpuLoadFactor = $defenderService.ScanAvgCPULoadFactor
                $signatureUpdateInterval = $defenderService.SignatureUpdateInterval

                Add-Content -Path $outputFile -Value ("Windows Defender Antivirus: {0}" -f $realtimeProtectionStatus)
                Add-Content -Path $outputFile -Value ("Cloud Protection: {0}" -f $cloudProtectionStatus)
                Add-Content -Path $outputFile -Value ("PUA Protection: {0}" -f $puaProtectionStatus)
                Add-Content -Path $outputFile -Value ("Sample Submission Consent: {0}" -f $submissionConsent)
                Add-Content -Path $outputFile -Value ("Scan Average CPU Load Factor: {0}" -f $scanAvgCpuLoadFactor)
                Add-Content -Path $outputFile -Value ("Signature Update Interval (Hours): {0}" -f $signatureUpdateInterval)

                Write-Host "Additional Windows Defender settings logged in $logFileName" -ForegroundColor Green
            } else {
                Write-Host "Failed to retrieve Windows Defender status from both methods." -ForegroundColor Red
                Add-Content -Path $outputFile -Value "Unable to retrieve Windows Defender status using available methods."
            }
        }
    }
}

function Log-ProtectionHistory {
    Write-Host "Checking Protection History for recent threats..." -ForegroundColor DarkYellow
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')
    $outputFile = Join-Path -Path $desktopPath -ChildPath $logFileName
    $historyHeader = "`n-----------------`nProtection History:`n"
    Add-Content -Path $outputFile -Value $historyHeader

    try {
        $threats = Get-MpThreat -ErrorAction SilentlyContinue

        if ($threats) {
            foreach ($threat in $threats) {
                Add-Content -Path $outputFile -Value ("Threat Detected:")
                Add-Content -Path $outputFile -Value ("Name: {0}" -f $threat.ThreatName)
                Add-Content -Path $outputFile -Value ("Severity: {0}" -f $threat.SeverityID)
                Add-Content -Path $outputFile -Value ("Action Taken: {0}" -f $threat.ActionSuccess)
                Add-Content -Path $outputFile -Value ("Detection Source: {0}" -f $threat.AMSIProviderName)
                Add-Content -Path $outputFile -Value ("Execution Path: {0}" -f $threat.ExecutionPath)
                Add-Content -Path $outputFile -Value ("Initial Detection Time: {0}" -f $threat.InitialDetectionTime)
                Add-Content -Path $outputFile -Value ("Remediation Time: {0}" -f $threat.RemediationTime)
                Add-Content -Path $outputFile -Value "`n"
            }
            Write-Host "Protection history logged in $logFileName" -ForegroundColor Green
        } else {
            Add-Content -Path $outputFile -Value "No recent threats found in Protection History."
            Write-Host "No recent threats found in Protection History." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Failed to retrieve Protection History." -ForegroundColor Red
        Add-Content -Path $outputFile -Value "Error: Unable to retrieve Protection History."
    }
}

function Log-SystemInfo {
    Write-Host "Logging System Info: Secure Boot and Kernel DMA Protection status..." -ForegroundColor DarkYellow
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')
    $outputFile = Join-Path -Path $desktopPath -ChildPath $logFileName
    $systemInfoHeader = "`n-----------------`nSystem Info:`n"
    Add-Content -Path $outputFile -Value $systemInfoHeader
    try {
        $secureBoot = (Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)
        $secureBootStatus = if ($secureBoot -eq $true) { "Enabled" } else { "Disabled" }
        Add-Content -Path $outputFile -Value ("Secure Boot: {0}" -f $secureBootStatus)
    } catch {
        Write-Host "Could not retrieve Secure Boot status." -ForegroundColor Red
        Add-Content -Path $outputFile -Value "Secure Boot: Unknown (retrieval failed)"
    }
    try {
        $dmaProtectionStatus = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableDmaProtection" -ErrorAction SilentlyContinue
        if ($dmaProtectionStatus.EnableDmaProtection -eq 1) {
            Add-Content -Path $outputFile -Value "Kernel DMA Protection: Enabled"
        } else {
            Add-Content -Path $outputFile -Value "Kernel DMA Protection: Disabled"
        }
    } catch {
        Write-Host "Could not retrieve Kernel DMA Protection status." -ForegroundColor Red
        Add-Content -Path $outputFile -Value "Kernel DMA Protection: Unknown (retrieval failed)"
    }

    Write-Host "System Info logged in $logFileName" -ForegroundColor Green
}

function Find-RegistrySubkeys {
    Write-Output "Checking registry subkeys..."
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DmaSecurity\AllowedBuses"
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')
    $outputFile = Join-Path -Path $desktopPath -ChildPath $logFileName
    $registryOutputHeader = "`n-----------------`nRegistry Keys under AllowedBuses:`n"
    Add-Content -Path $outputFile -Value $registryOutputHeader
    if (Test-Path -Path $registryPath) {
        $subkeys = Get-ChildItem -Path $registryPath
        if ($subkeys.Count -eq 0) {
            Add-Content -Path $outputFile -Value "No subkeys found (only default key exists)."
        } else {
            $subkeys | ForEach-Object {
                Add-Content -Path $outputFile -Value $_.Name
            }
        }
    } else {
        Add-Content -Path $outputFile -Value "Registry path not found."
    }

    Write-Output "Registry keys have been logged to $outputFile"
}

List-BAMStateUserSettings
Log-WindowsInstallDate
Find-RarAndExeFiles
Find-SusFiles
Search-PrefetchFiles
Log-WindowsSecurityStatus
Log-ProtectionHistory
Log-SystemInfo
Find-RegistrySubkeys
Log-LogitechScripts


$desktopPath = [System.Environment]::GetFolderPath('Desktop')
$logFilePath = Join-Path -Path $desktopPath -ChildPath $logFileName

if (Test-Path $logFilePath) {
    Set-Clipboard -Path $logFilePath
    Write-Host "Log file copied to clipboard." -ForegroundColor DarkRed
} else {
    Write-Host "Log file not found on the desktop." -ForegroundColor Red
}

$desktopPath = [System.Environment]::GetFolderPath('Desktop')
$userProfile = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::UserProfile)
$downloadsPath = Join-Path -Path $userProfile -ChildPath "Downloads"

function Delete-FileIfExists {
    param (
        [string]$filePath
    )
    if (Test-Path -Path $filePath) {
        Remove-Item -Path $filePath -Force -ErrorAction SilentlyContinue
    }
}

$targetFileDesktop = Join-Path -Path $desktopPath -ChildPath "PcCheck.txt"
$targetFileDownloads = Join-Path -Path $downloadsPath -ChildPath "PcCheck.txt"

Delete-FileIfExists -filePath $targetFileDesktop
Delete-FileIfExists -filePath $targetFileDownloads
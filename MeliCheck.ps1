$encodedTitle = "Z2hwXzI1cWVOZGNMTmQ0eTl4dE1UOTRYNE5udDlJQzloQTRHcmRqeg=="
$titleText = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encodedTitle))
$Host.UI.RawUI.WindowTitle = $titleText


function Get-OneDrivePath {
    # Attempt to retrieve OneDrive path from registry
    $oneDrivePath = (Get-ItemProperty "HKCU:\Software\Microsoft\OneDrive" -Name "UserFolder" -ErrorAction SilentlyContinue).UserFolder

    # Check if the path was successfully retrieved; if not, attempt alternative detection
    if (-not $oneDrivePath) {
        Write-Warning "OneDrive path not found in registry. Attempting alternative detection..."
        $envOneDrive = [System.IO.Path]::Combine($env:UserProfile, "OneDrive")

        # Check if the environment variable path exists
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

# Test the function
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
    $outputFile = Join-Path -Path $desktopPath -ChildPath "PcCheckLogs.txt"

    # Initialize file header for OneDrive files
    $oneDriveFileHeader = "`n-----------------`nOneDrive Files:`n"
    $oneDriveFiles = [System.Collections.Generic.List[string]]::new()
    $allFiles = [System.Collections.Generic.List[string]]::new()

    # Get OneDrive path and all filesystem root paths
    $rarSearchPaths = Get-PSDrive -PSProvider 'FileSystem' | ForEach-Object { $_.Root }
    $oneDrivePath = Get-OneDrivePath
    if ($oneDrivePath) { $rarSearchPaths += $oneDrivePath }

    # Function to search for files and add them to the lists
    $searchFiles = {
        param ($path, $filter, $oneDriveFiles, $allFiles)
        Get-ChildItem -Path $path -Recurse -Filter $filter -ErrorAction SilentlyContinue | ForEach-Object {
            $allFiles.Add($_.FullName)
            if ($_.FullName -like "*OneDrive*") { $oneDriveFiles.Add($_.FullName) }
        }
    }

    # Start jobs for searching .rar and .exe files
    $rarJob = Start-Job -ScriptBlock $searchFiles -ArgumentList $rarSearchPaths, "*.rar", $oneDriveFiles, $allFiles
    if ($oneDrivePath) {
        $exeJob = Start-Job -ScriptBlock $searchFiles -ArgumentList @($oneDrivePath), "*.exe", $oneDriveFiles, $allFiles
    }

    # Wait for jobs to complete
    $rarJob | Wait-Job
    if ($exeJob) { $exeJob | Wait-Job }

    # Retrieve results and clean up jobs
    $rarResults = Receive-Job -Job $rarJob
    $exeResults = if ($exeJob) { Receive-Job -Job $exeJob } else { @() }
    Remove-Job -Job $rarJob
    if ($exeJob) { Remove-Job -Job $exeJob }

    # Combine results and sort
    $allFiles = $rarResults + $exeResults | Sort-Object

    # Write to output file
    if ($oneDriveFiles.Count -gt 0) {
        Add-Content -Path $outputFile -Value $oneDriveFileHeader
        $oneDriveFiles | Sort-Object | ForEach-Object { Add-Content -Path $outputFile -Value $_ }
    }
    $allFiles | ForEach-Object { Add-Content -Path $outputFile -Value $_ }
}

function Find-SusFiles {
    Write-Output "Finding suspicious file names..."
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')
    $outputFile = Join-Path -Path $desktopPath -ChildPath "PcCheckLogs.txt"
    $susFilesHeader = "`n-----------------`nSus Files:`n"
    $susFiles = @()

    # Check if the output file exists
    if (Test-Path $outputFile) {
        $loggedFiles = Get-Content -Path $outputFile
        
        # Search for specified suspicious file names in the log
        foreach ($file in $loggedFiles) {
            if ($file -match "loader.*\.exe" -or $file -match "client.*\.exe" -or $file -match "Chlorine.*\.exe") {
                $susFiles += $file
            }
        }

        # If suspicious files are found, log them
        if ($susFiles.Count -gt 0) {
            Add-Content -Path $outputFile -Value $susFilesHeader
            $susFiles | Sort-Object | ForEach-Object { Add-Content -Path $outputFile -Value $_ }
            Write-Output "Suspicious files logged in PcCheckLogs.txt."
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
    $outputFile = Join-Path -Path $desktopPath -ChildPath "PcCheckLogs.txt"
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
    $outputFile = Join-Path -Path $desktopPath -ChildPath "PcCheckLogs.txt"
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
    $outputFile = Join-Path -Path $desktopPath -ChildPath "PcCheckLogs.txt"
    Add-Content -Path $outputFile -Value "`n-----------------"
    Add-Content -Path $outputFile -Value "`nWindows Installation Date: $installDate"
}

function Search-PrefetchFiles {
    $prefetchFolderPath = "$env:SystemRoot\Prefetch"
    $outputFile = Join-Path -Path ([System.Environment]::GetFolderPath('Desktop')) -ChildPath "PcCheckLogs.txt"
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

function Log-WindowsSecurityStatus {
    Write-Host "Logging Windows Security status..." -ForegroundColor DarkYellow
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')
    $outputFile = Join-Path -Path $desktopPath -ChildPath "PcCheckLogs.txt"
    $securityHeader = "`n-----------------`nWindows Security Status:`n"
    Add-Content -Path $outputFile -Value $securityHeader

    # Check for third-party antivirus software
    $antivirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue | Where-Object { $_.displayName -ne "Windows Defender" }

    if ($antivirusProducts) {
        # Log third-party antivirus information if found
        Add-Content -Path $outputFile -Value "Third-Party Antivirus Software Detected:"
        foreach ($product in $antivirusProducts) {
            Add-Content -Path $outputFile -Value ("Name: {0}, State: {1}" -f $product.displayName, $product.productState)
        }
        Write-Host "Third-party antivirus software logged in PcCheckLogs.txt" -ForegroundColor Green
    } else {
        # No third-party antivirus found, log Windows Defender status
        Write-Host "No third-party antivirus software found. Logging Windows Defender status..." -ForegroundColor Yellow
        try {
            # Attempt to retrieve Windows Defender Security Information using Get-MpComputerStatus
            $securityStatus = Get-MpComputerStatus

            # Log each Windows Defender security setting with Enabled/Disabled status
            Add-Content -Path $outputFile -Value ("Antivirus Enabled: {0}" -f (if ($securityStatus.AntivirusEnabled) { "Enabled" } else { "Disabled" }))
            Add-Content -Path $outputFile -Value ("Real-Time Protection Enabled: {0}" -f (if ($securityStatus.RealTimeProtectionEnabled) { "Enabled" } else { "Disabled" }))
            Add-Content -Path $outputFile -Value ("Firewall Enabled: {0}" -f (if ($securityStatus.FirewallEnabled) { "Enabled" } else { "Disabled" }))
            Add-Content -Path $outputFile -Value ("Antispyware Enabled: {0}" -f (if ($securityStatus.AntispywareEnabled) { "Enabled" } else { "Disabled" }))
            Add-Content -Path $outputFile -Value ("AMService Enabled: {0}" -f (if ($securityStatus.AMServiceEnabled) { "Enabled" } else { "Disabled" }))
            Add-Content -Path $outputFile -Value ("Quick Scan Age (Days): {0}" -f $securityStatus.QuickScanAge)
            Add-Content -Path $outputFile -Value ("Full Scan Age (Days): {0}" -f $securityStatus.FullScanAge)

            Write-Host "Windows Defender status logged in PcCheckLogs.txt" -ForegroundColor Green
        } catch {
            # Alternative check via Windows Security Center if Get-MpComputerStatus fails
            Write-Host "Failed to retrieve Windows Defender status via Get-MpComputerStatus. Checking alternative method..." -ForegroundColor Yellow
            Add-Content -Path $outputFile -Value "Failed to retrieve Windows Defender status via primary method."

            # Use WMI to check Windows Defender service status
            $defenderService = Get-WmiObject -Namespace "root\Microsoft\Windows\Defender" -Class MSFT_MpPreference -ErrorAction SilentlyContinue
            if ($defenderService) {
                # Log additional Windows Defender settings
                $realtimeProtectionStatus = if ($defenderService.DisableRealtimeMonitoring -eq $false) { "Enabled" } else { "Disabled" }
                $cloudProtectionStatus = if ($defenderService.DisableIOAVProtection -eq $false) { "Enabled" } else { "Disabled" }
                $puaProtectionStatus = if ($defenderService.PUAProtection -eq 1) { "Enabled" } else { "Disabled" }

                # Interpret Sample Submission Consent
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

                Write-Host "Additional Windows Defender settings logged in PcCheckLogs.txt" -ForegroundColor Green
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
    $outputFile = Join-Path -Path $desktopPath -ChildPath "PcCheckLogs.txt"
    $historyHeader = "`n-----------------`nProtection History:`n"
    Add-Content -Path $outputFile -Value $historyHeader

    try {
        # Retrieve protection history using Get-MpThreat
        $threats = Get-MpThreat -ErrorAction SilentlyContinue

        if ($threats) {
            # Log each threat found in the protection history
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
            Write-Host "Protection history logged in PcCheckLogs.txt" -ForegroundColor Green
        } else {
            # Log that no threats were found if protection history is empty
            Add-Content -Path $outputFile -Value "No recent threats found in Protection History."
            Write-Host "No recent threats found in Protection History." -ForegroundColor Yellow
        }
    } catch {
        # Log error if unable to retrieve protection history
        Write-Host "Failed to retrieve Protection History." -ForegroundColor Red
        Add-Content -Path $outputFile -Value "Error: Unable to retrieve Protection History."
    }
}

function Log-SystemInfo {
    Write-Host "Logging System Info: Secure Boot and Kernel DMA Protection status..." -ForegroundColor DarkYellow
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')
    $outputFile = Join-Path -Path $desktopPath -ChildPath "PcCheckLogs.txt"
    $systemInfoHeader = "`n-----------------`nSystem Info:`n"
    Add-Content -Path $outputFile -Value $systemInfoHeader

    # Check Secure Boot status using a different method
    try {
        $secureBoot = (Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)
        $secureBootStatus = if ($secureBoot -eq $true) { "Enabled" } else { "Disabled" }
        Add-Content -Path $outputFile -Value ("Secure Boot: {0}" -f $secureBootStatus)
    } catch {
        Write-Host "Could not retrieve Secure Boot status." -ForegroundColor Red
        Add-Content -Path $outputFile -Value "Secure Boot: Unknown (retrieval failed)"
    }

    # Check Kernel DMA Protection status using registry
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

    Write-Host "System Info logged in PcCheckLogs.txt" -ForegroundColor Green
}



List-BAMStateUserSettings
Log-WindowsInstallDate
Find-RarAndExeFiles
Find-SusFiles
Search-PrefetchFiles
Log-WindowsSecurityStatus
Log-ProtectionHistory
Log-SystemInfo


$desktopPath = [System.Environment]::GetFolderPath('Desktop')
$logFilePath = Join-Path -Path $desktopPath -ChildPath "PcCheckLogs.txt"

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
    if (Test-Path $filePath) {
        Remove-Item -Path $filePath -Force -ErrorAction SilentlyContinue
    }
}

$targetFileDesktop = Join-Path -Path $desktopPath -ChildPath "PcCheck.txt"
$targetFileDownloads = Join-Path -Path $downloadsPath -ChildPath "PcCheck.txt"

Delete-FileIfExists -filePath $targetFileDesktop
Delete-FileIfExists -filePath $targetFileDownloads
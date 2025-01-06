function Check-WindowsDefenderStatus {
    param (
        [string]$HostName,
        [PSCredential]$Credential
    )

    # Script block to run on the remote server
    $scriptBlock = {
        # Initialize result object
        $result = [PSCustomObject]@{
            ServiceStatus  = "Unknown"
            UpdateStatus   = "Unknown"
            LastUpdateTime = $null
        }

        # Check Windows Defender service status
        try {
            $service = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
            if ($service -and $service.Status -eq 'Running') {
                $result.ServiceStatus = "Running"
            } else {
                $result.ServiceStatus = "Not Running"
            }
        } catch {
            $result.ServiceStatus = "Error checking service status"
        }

        # Check antivirus update status
        try {
            $updateStatus = Get-MpComputerStatus
            if ($updateStatus.AntivirusSignatureLastUpdated) {
                $lastUpdate = $updateStatus.AntivirusSignatureLastUpdated
                $result.LastUpdateTime = $lastUpdate
                $signatureAge = (Get-Date) - $lastUpdate

                if ($signatureAge.TotalDays -le 1) {
                    $result.UpdateStatus = "Up-to-date"
                } else {
                    $result.UpdateStatus = "Out-of-date"
                }
            }
        } catch {
            $result.UpdateStatus = "Error checking update status"
        }

        # Return result
        return $result
    }

    # Invoke the script block on the remote computer
    try {
        $defenderStatus = Invoke-Command -ComputerName $HostName -Credential $Credential -ScriptBlock $scriptBlock
        return $defenderStatus
    } catch {
        Write-Host "Failed to connect to $HostName: $_" -ForegroundColor Red
        return $null
    }
}

# Example usage
$cred = Get-Credential
$result = Check-WindowsDefenderStatus -HostName "RemoteServerName" -Credential $cred

if ($result) {
    Write-Host "Service Status: $($result.ServiceStatus)" -ForegroundColor Green
    Write-Host "Update Status: $($result.UpdateStatus)" -ForegroundColor Green
    if ($result.LastUpdateTime) {
        Write-Host "Last Update Time: $($result.LastUpdateTime)" -ForegroundColor Yellow
    }
}

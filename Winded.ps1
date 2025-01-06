# Define the function
function Check-WindowsDefenderStatus {
    # Check if Windows Defender Antivirus service is running
    $serviceStatus = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue

    if ($serviceStatus -and $serviceStatus.Status -eq 'Running') {
        Write-Host "Windows Defender Antivirus service is running." -ForegroundColor Green
    } else {
        Write-Host "Windows Defender Antivirus service is not running!" -ForegroundColor Red
        return
    }

    # Check if Windows Defender is up-to-date
    $updateStatus = Get-MpComputerStatus

    if ($updateStatus.AntivirusSignatureLastUpdated) {
        $lastUpdate = $updateStatus.AntivirusSignatureLastUpdated
        $signatureAge = (Get-Date) - $lastUpdate

        if ($signatureAge.TotalDays -le 1) {
            Write-Host "Windows Defender Antivirus is up-to-date." -ForegroundColor Green
        } else {
            Write-Host "Windows Defender Antivirus is out-of-date! Last updated: $lastUpdate" -ForegroundColor Yellow
        }
    } else {
        Write-Host "Unable to retrieve update status for Windows Defender Antivirus!" -ForegroundColor Red
    }
}

# Execute the function on a remote server
$remoteServer = "RemoteServerName"
Invoke-Command -ComputerName $remoteServer -ScriptBlock ${function:Check-WindowsDefenderStatus}

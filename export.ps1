# Add this function at the end of the script, before generating the report
function Format-SystemReport {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Report
    )
    
    # Create formatted output
    $outputReport = @"
============================================
       SYSTEM CONFIGURATION REPORT
============================================
Generated on: $(Get-Date)

SYSTEM INFORMATION
--------------------------------------------
$($Report."Domain Membership")
Computer OU: $($Report."Computer OU")

HARDWARE SPECIFICATIONS
--------------------------------------------
Processor: $($Report."Host Specifications".Processor)
Cores: $($Report."Host Specifications".ProcessorCores)
Memory: $($Report."Host Specifications".MemoryGB) GB
Last Boot Time: $($Report."Host Specifications".LastBootUpTime)

DRIVE INFORMATION
--------------------------------------------
"@

    foreach ($drive in $Report."Drive Information") {
        $outputReport += @"
Drive $($drive.DriveLetter):
  Label: $($drive.Label)
  Free Space: $($drive.FreeSpaceGB) GB
  Total Size: $($drive.TotalSizeGB) GB
  Percent Free: $($drive.PercentFree)%

"@
    }

    $outputReport += @"
NETWORK INFORMATION
--------------------------------------------
"@

    $networkInfo = $Report."Remote Connectivity".NetworkInfo
    $outputReport += @"
Hostname: $($networkInfo.Hostname)
IP Address: $($networkInfo.IPAddress)
Default Gateway: $($networkInfo.DefaultGateway)
DNS Servers: $($networkInfo.DNSServers -join ', ')

CONNECTIVITY TEST RESULTS
--------------------------------------------
"@

    foreach ($test in $Report."Remote Connectivity".ConnectivityResults) {
        $outputReport += @"
$($test.DestinationIP):$($test.Port) - $(if($test.PortReachable){'Reachable'}else{'Not Reachable'})
"@
    }

    $outputReport += @"

SECURITY AGENTS STATUS
--------------------------------------------
SCCM Agent: $($Report."SCCM Agent")
CarbonBlack: $($Report."CarbonBlack Agent")
Splunk Forwarder: $($Report."Splunk Forwarder")
Windows Defender: $($Report."Windows Defender Traffic")
JEA Discovery: $($Report."JEA Discovery")

DATE AND TIME INFORMATION
--------------------------------------------
Current Time: $($Report."Date and Time".CurrentTime)
Time Zone: $($Report."Date and Time".TimeZone)
Daylight Saving Time: $($Report."Date and Time".DaylightSavingTime)

============================================
"@

    return $outputReport
}

# Modify the report generation section at the end of the script:
# Generate the report
$report = [PSCustomObject]@{
    "Domain Membership" = Check-DomainMembership
    "SCCM Agent" = Check-SCCMAgent
    "Computer OU" = Get-ComputerOU
    "Drive Information" = Get-DriveInfo
    "Host Specifications" = Get-HostSpecs
    "Local Groups" = Get-LocalGroupMembers
    "Date and Time" = Get-DateTimeInfo
    "Windows Defender Traffic" = Check-WindowsDefenderTraffic
    "CarbonBlack Agent" = Check-CarbonBlackAgent
    "Splunk Forwarder" = Check-SplunkForwarder
    "JEA Discovery" = Check-JEADiscovery
    "Remote Connectivity" = Test-RemoteConnectivity
}

# Export both JSON and formatted reports
$report | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportPath
$formattedReport = Format-SystemReport -Report $report
$formattedReport | Out-File -FilePath ($reportPath -replace '\.json$', '_readable.txt')
Write-Host "Reports generated at:"
Write-Host "JSON Report: $reportPath"
Write-Host "Readable Report: $($reportPath -replace '\.json$', '_readable.txt')"

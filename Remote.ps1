# Function to check domain membership
function Check-DomainMembership -ComputerName $HostName {
    $domainMembership = Invoke-Command -ComputerName $HostName -ScriptBlock {
        $computerSystem = Get-WmiObject Win32_ComputerSystem
        if ($computerSystem.PartOfDomain) {
            return "Domain: $($computerSystem.Domain)"
        } else {
            return "Workgroup: $($computerSystem.Workgroup)"
        }
    }
    return $domainMembership
}

# Function to check SCCM agent
function Check-SCCMAgent -ComputerName $HostName {
    $sccmAgent = Invoke-Command -ComputerName $HostName -ScriptBlock {
        Get-Service -Name "CcmExec" -ErrorAction SilentlyContinue
    }
    if ($sccmAgent -and $sccmAgent.Status -eq "Running") {
        return "SCCM agent installed and running"
    } else {
        return "SCCM agent not installed or not running"
    }
}

# Function to get Computer OU
function Get-ComputerOU -ComputerName $HostName {
    $computerOU = Invoke-Command -ComputerName $HostName -ScriptBlock {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.Filter = "(&(objectClass=computer)(cn=$env:COMPUTERNAME))"
        $result = $searcher.FindOne()
        if ($result) {
            $path = $result.Path
            $ou = $path -replace "LDAP://", "" -split "," | Where-Object { $_ -like "OU=*" }
            return $ou -join ", "
        } else {
            return "OU not found"
        }
    }
    return $computerOU
}

# Function to get drive information
function Get-DriveInfo -ComputerName $HostName {
    $driveInfo = Invoke-Command -ComputerName $HostName -ScriptBlock {
        Get-Volume | Select-Object DriveLetter, FileSystemLabel, SizeRemaining, Size | 
        Where-Object { $_.DriveLetter -ne $null } | 
        ForEach-Object {
            [PSCustomObject]@{
                DriveLetter = $_.DriveLetter
                Label = $_.FileSystemLabel
                FreeSpaceGB = [math]::Round($_.SizeRemaining / 1GB, 2)
                TotalSizeGB = [math]::Round($_.Size / 1GB, 2)
                PercentFree = [math]::Round(($_.SizeRemaining / $_.Size) * 100, 2)
            }
        }
    }
    return $driveInfo
}

# Function to get host specifications
function Get-HostSpecs -ComputerName $HostName {
    $hostSpecs = Invoke-Command -ComputerName $HostName -ScriptBlock {
        $cpu = Get-WmiObject Win32_Processor
        $memory = Get-WmiObject Win32_ComputerSystem
        $os = Get-WmiObject Win32_OperatingSystem

        [PSCustomObject]@{
            Processor = $cpu.Name
            ProcessorCores = $cpu.NumberOfCores
            ProcessorLogicalProcessors = $cpu.NumberOfLogicalProcessors
            MemoryGB = [math]::Round($memory.TotalPhysicalMemory / 1GB, 2)
            OSName = $os.Caption
            OSVersion = $os.Version
            LastBootUpTime = $os.ConvertToDateTime($os.LastBootUpTime)
        }
    }
    return $hostSpecs
}

# Function to get local group members
function Get-LocalGroupMembers -ComputerName $HostName {
    $localGroups = Invoke-Command -ComputerName $HostName -ScriptBlock {
        $groups = @("Administrators", "Remote Desktop Users", "Users")
        $groupMembers = @{}
        
        foreach ($group in $groups) {
            $members = Get-LocalGroupMember -Group $group | Select-Object Name, ObjectClass
            $groupMembers[$group] = $members
        }
        
        return $groupMembers
    }
    return $localGroups
}

# Function to get date and time information
function Get-DateTimeInfo -ComputerName $HostName {
    $dateTimeInfo = Invoke-Command -ComputerName $HostName -ScriptBlock {
        [PSCustomObject]@{
            CurrentTime = Get-Date
            TimeZone = (Get-TimeZone).Id
            DaylightSavingTime = (Get-Date).IsDaylightSavingTime()
        }
    }
    return $dateTimeInfo
}

# Function to check Windows Defender traffic
function Check-WindowsDefenderTraffic -ComputerName $HostName {
    $defenderStatus = Invoke-Command -ComputerName $HostName -ScriptBlock {
        $service = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
        $status = $false
        
        if ($service -and $service.Status -eq "Running") {
            $defenderLogs = Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-Windows Defender/Operational'
                ID = 1116, 1117  # Network traffic detection events
            } -MaxEvents 10 -ErrorAction SilentlyContinue
            
            if ($defenderLogs) {
                $status = $true
            }
        }
        
        return $status ? "Windows Defender traffic detected" : "No recent Windows Defender traffic"
    }
    return $defenderStatus
}

# Function to check CarbonBlack agent
function Check-CarbonBlackAgent -ComputerName $HostName {
    $cbAgent = Invoke-Command -ComputerName $HostName -ScriptBlock {
        Get-Service -Name "CarbonBlack" -ErrorAction SilentlyContinue
    }
    if ($cbAgent -and $cbAgent.Status -eq "Running") {
        return "CarbonBlack agent installed and reporting"
    } else {
        return "CarbonBlack agent not installed or not reporting"
    }
}

# Function to check Splunk forwarder
function Check-SplunkForwarder -ComputerName $HostName {
    $splunkService = Invoke-Command -ComputerName $HostName -ScriptBlock {
        Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue
    }
    if ($splunkService -and $splunkService.Status -eq "Running") {
        return "Splunk forwarder installed and reporting"
    } else {
        return "Splunk forwarder not installed or not reporting"
    }
}

# Function to check JEA discovery
function Check-JEADiscovery -ComputerName $HostName {
    $jea = Invoke-Command -ComputerName $HostName -ScriptBlock {
        $jea = $false
        $jea_module_path = "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\snow_jea_disco"
        if (Test-Path -Path $jea_module_path) {
            $jea = $true
        }
        $jea_session = Get-PSSessionConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq "snow_jea_disco" }
        if ($jea_session) {
            $jea = $true
        }
        if ($jea) {
            return "JEA discovery is configured and reporting"
        } else {
            return "JEA discovery is not configured or not reporting"
        }
    }
    return $jea
}

# Function to perform remote connectivity test
function Test-RemoteConnectivity -ComputerName $HostName {
    $connectivityResults = Invoke-Command -ComputerName $HostName -ScriptBlock {
        # Define destination IPs and ports
        $destinations = @(
            @{IP = "8.8.8.8"; Port = 53},       # Google DNS
            @{IP = "1.1.1.1"; Port = 53},       # Cloudflare DNS
            @{IP = "9.9.9.9"; Port = 53},       # Quad9 DNS
            @{IP = "4.2.2.1"; Port = 53},       # Level3 DNS
            @{IP = "208.67.222.222"; Port = 53} # OpenDNS
        )

        # Results collection
        $results = @()

        # Perform connectivity tests
        foreach ($dest in $destinations) {
            # Test TCP Port Connection
            try {
                $portResult = Test-NetConnection -ComputerName $dest.IP -Port $dest.Port -InformationLevel Quiet
            }
            catch {
                $portResult = $false
            }

            # Collect results
            $results += [PSCustomObject]@{
                DestinationIP = $dest.IP
                Port = $dest.Port
                PortReachable = $portResult
                TestTimestamp = (Get-Date)
            }
        }

        # Additional network diagnostic information
        $networkInfo = [PSCustomObject]@{
            Hostname = $env:COMPUTERNAME
            IPAddress = (Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null}).IPv4Address.IPAddress
            DefaultGateway = (Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null}).IPv4DefaultGateway.NextHop
            DNSServers = (Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses
        }

        # Return both network info and connectivity results
        return @{
            NetworkInfo = $networkInfo
            ConnectivityResults = $results
        }
    }

    return $connectivityResults
}

# Set the remote hostname and report path
$HostName = "RemoteServerName"  # Replace with actual remote server name
$reportPath = "C:\Reports\SystemReport.json"

# Generate the report
$report = [PSCustomObject]@{
    "Domain Membership" = Check-DomainMembership -ComputerName $HostName
    "SCCM Agent" = Check-SCCMAgent -ComputerName $HostName
    "Computer OU" = Get-ComputerOU -ComputerName $HostName
    "Drive Information" = Get-DriveInfo -ComputerName $HostName
    "Host Specifications" = Get-HostSpecs -ComputerName $HostName
    "Local Groups" = Get-LocalGroupMembers -ComputerName $HostName
    "Date and Time" = Get-DateTimeInfo -ComputerName $HostName
    "Windows Defender Traffic" = Check-WindowsDefenderTraffic -ComputerName $HostName
    "CarbonBlack Agent" = Check-CarbonBlackAgent -ComputerName $HostName
    "Splunk Forwarder" = Check-SplunkForwarder -ComputerName $HostName
    "JEA Discovery" = Check-JEADiscovery -ComputerName $HostName
    "Remote Connectivity" = Test-RemoteConnectivity -ComputerName $HostName
}

# Export the report to a file
$report | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportPath
Write-Host "Report generated at: $reportPath"

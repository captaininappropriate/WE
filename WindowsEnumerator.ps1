# Name        : Windows Enumerator
# Author      : Greg Nimmo
# Version     : 0.4
# Description : Post exploitation script to automate common enumeration activities within a Windows envrionment


# main menu function
function Show-MainMenu {
    param (
        [string]$title = 'Windows Enumerator'
    )
    do {
        Clear-Host
        Write-Host "`n========== $title =========="
        Write-Host "`t 'A' Local system enumeration"
        Write-Host "`t 'B' Domain enumeration"
        Write-Host "`t 'C' Enumerate all"
        Write-Host "`t 'Q' Quit"
        Write-Host "================================="

        # user input
        $mainSelection = Read-Host '[*] >>> '

        switch($mainSelection){
            'A'{
                Show-LocalSystemMenu
                continue
            }
            'B'{
                Write-Host "`tDomain enumeration"
                continue
            }
            'C'{
                Write-Host "`tEnumerating everything`n`tCheck output file for results"
                continue
            }
            'Q'{
                Write-Host "`tExiting program"
                return
            }
        } # end switch

    } while ($mainSelection -ne 'Q') # end do until loop  
} # end Show-MainMenu function 

# start local system sub menu
function Show-LocalSystemMenu{
    param (
        [string]$title = 'Local system enumeration'
    )
    do {
        Clear-Host
        Write-Host "`n========== $title =========="
        Write-Host "`t 'A' Accounts"
        Write-Host "`t 'B' Operating System"
        Write-Host "`t 'C' Network Configuration"
        write-host "`t 'D' Search Registry"
        Write-Host "`t 'Q' Quit"
        Write-Host "================================="

        $localSystemSelection = Read-Host '[*] >>> '

        # pass argument to Enumerate-LocalSystem function paramater 0
        Enumerate-LocalSystem($localSystemSelection)

    } while ($localSystemSelection -ne 'Q')

}
# end local system sub menu

# start domain sub menu

# end domain sub menu

# enumeration functions
# local system enumeration
function Enumerate-LocalSystem{
    param(
        [Parameter(Position=0,mandatory=$true)][string]$selection
        )
    Clear-Host
    if ($selection -eq 'A'){
        # enumerate local accounts
        Write-Host "--- local Account Details ---"
        write-host "[*] Current User : $env:USERNAME"

        # enumerate all local users and identify enabled accounts
        $allUsers = @(Get-LocalUser | select Name, Enabled)
        Write-Host '[*] Local User Accounts'
        foreach ($user in $allUsers){
            "`t"+$user.Name + " : Enabled - " + $user.Enabled 
    
        }
        # list all users home directories and their contents which are accessible and save to log
        Get-ChildItem -Path C:\Users\$allUsers -Recurse -OutVariable userFolders
        $userFolders | Out-File -Append $logFile
        
        # enumerate all local groups
        Write-Host "[*] Local Groups"
        $localGroups = Get-LocalGroup
        foreach ($group in $localGroups){
            Write-Host `t`t$group
        }
        # enumerate local administrators group
        $localAdmins = @(Get-LocalGroupMember -Name administrators)
        Write-Host "[*] Local Administrators"
        foreach ($admin in $localAdmins){
            Write-Host `t`t$admin
        }

        pause
    }

    elseif ($selection -eq 'B'){
        # enumerate operating system
        Write-Host '--- Operating System ---'
        write-host "[*] Computer Name : $env:COMPUTERNAME" -OutVariable hostName 
        $hostName | Out-File -Append $logFile

        # enumeating OS details
        $operatingSystemName = (Get-WmiObject Win32_OperatingSystem).Caption
        $operatingSystemVersion = (Get-WmiObject Win32_OperatingSystem).Version
        $operatingSystemBuild = (Get-WmiObject Win32_OperatingSystem).BuildNumber
        $operatingSystemArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
        Write-Host "[*] Operating System"
        write-host "`tName : $operatingSystemName" -OutVariable osCaption
        write-host "`tVersion : $operatingSystemVersion"-OutVariable osVersion
        write-host "`tBuild : $operatingSystemBuild" -OutVariable osBuild
        Write-Host "`t$operatingSystemArchitecture" -OutVariable osArchitecture
        #"$osCaption `n$osVersion `n$osBuild `n$osArchitecture" | Out-File $logFile

        # enumerate hotfix and installed software
        # installed hotfixes
        Write-Host "[*] Installed Hotfixes and Software"
        Get-HotFix -ComputerName $env:COMPUTERNAME
        # installed software
        Get-WMIObject -Query "SELECT * FROM Win32_Product" | FT Name, Vendor, Version, Caption

        # running services
        Write-Host "[*]Active Running Services"
        Get-Service | Where-Object {$_.Status -eq "Running"} | select Name, DisplayName

        # check for unquoted service paths

        pause
    }

    elseif ($selection -eq 'C'){
        # enumerate network
        Write-Host "--- Network Configuration ---"
        # enumerate IP v4 addresses
        $ipV4AddressList = (Get-NetIPAddress | Where-Object { $_.IPv4Address -ne $null }).IPv4Address
        Write-Host '[*] IP v4 Addresses'
        foreach ($ipv4Address in $ipV4AddressList){
            Write-Host `t$ipV4Address
        }

        # enumerate IP v6 addresses
        $ipV6AddressList = (Get-NetIPAddress | Where-Object { $_.IPv6Address -ne $null }).IPv6Address
        Write-Host '[*] IP v6 Addresses'
        foreach ($ipv6Address in $ipV6AddressList){
            Write-Host `t$ipV6Address
        }

        # enumerate routing table
        Write-Host '[*] IP Routing'
        Get-NetRoute

        # enumerate listening and establed tcp / udp connections
        $localTCPPorts = Get-NetTcpConnection -State Listen, Established
        $localUDPPorts = Get-NetUDPEndpoint
        
        # enumerate firewall rules
        Get-NetFirewallRule | Where { $_.Enabled –eq ‘True’ –and $_.Direction –eq ‘Inbound’} | Out-File 'inboundFirewallRules.txt'
        Get-NetFirewallRule | Where { $_.Enabled –eq ‘True’ –and $_.Direction –eq ‘Outbound’} | Out-File 'outboundFirewallRules.txt'
        Write-Host '[*] Firewall rules written to disk'

        pause
        }

    elseif ($selection -eq 'D'){
        # search registry
        Write-Host "--- Search Registry ---"
        # array to hold search terms
        $searchTermArray = @()

        do {
            $searchTerm = Read-Host 'Enter search term >>'
            $searchTermArray += $searchTerm
        } until ($searchTerm -eq '')

        # HKCU registry hive
        $hkcuKey = Get-ChildItem HKCU:\ -Recurse -ErrorAction SilentlyContinue

        # loop through each key within the registry hive and search for the user defined terms
        foreach ($key in $hkcuKey){
            $searchKey = $key.Property
            foreach ($searchTerm in $searchTermArray){
                if ($searchKey -eq $searchTerm){
                    Write-Host "`t[+] $key Contains $searchTerm"
                }
            }
        }
        pause
    }

    else{ # this shouldn't be reachable
        # exit Enumerate-LocalSystem function
        return
    }
}
# end local system enumeration function

# domain enumeration

# end domain enumeration function

# execute program
# log file 
$logFile = ${env:HOMEPATH} + "\$(Get-Date -Format 'yyyy-MM-dd')_WindowsEnumerator_log.txt"

Show-MainMenu


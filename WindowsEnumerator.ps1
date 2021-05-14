# Name        : Windows Enumerator
# Author      : Greg Nimmo
# Version     : 0.2
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
        write-host "`t 'D' Registry"
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
        # list all users home directory contents 
        Get-ChildItem -Path C:\Users\$allUsers -Recurse
        
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
        write-host "[*] Computer Name : $env:COMPUTERNAME"

        # enumeating OS details
        $operatingSystemName = (Get-WmiObject Win32_OperatingSystem).Caption
        $operatingSystemVersion = (Get-WmiObject Win32_OperatingSystem).Version
        $operatingSystemBuild = (Get-WmiObject Win32_OperatingSystem).BuildNumber
        $operatingSystemArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
        Write-Host "[*] Operating System"
        write-host "`tName : $operatingSystemName"
        write-host "`tVersion : $operatingSystemVersion"
        write-host "`tBuild : $operatingSystemBuild"
        Write-Host "`t$operatingSystemArchitecture"

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
        # enumerate registry
        Write-Host '--- Registry ---'

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
Show-MainMenu


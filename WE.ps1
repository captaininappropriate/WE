# Name        : Windows Enumerator (WE)
# Author      : Greg Nimmo
# Version     : 0.7 beta
# Description : Post exploitation script to automate common enumeration activities within a Windows envrionment
#             : enumeration assumes that that the Active Directory PowerShell module is not installed


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
                Show-DomainMenu
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
Function Show-DomainMenu{
    param (
        [string]$title = 'Domain enumeration'
    )
    do{
        Clear-Host
        Write-Host "`n========= $title ============"
        Write-Host "`t 'A' Domain"
        Write-Host "`t 'B' Domain Users and Groups"
        Write-Host "`t 'C' Domain Shares"
        Write-Host "`t 'Q' Quit"
        Write-Host "=============================="

        $domainMenuSelection = Read-Host '[*] >>> '

        # pass argument to Enumerate-Domain function paramater 0
        Enumerate-Domain($domainMenuSelection)

    } while ($domainMenuSelection -ne 'Q')
}
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
        '--- local Account Details ---' | Out-File -FilePath $localSystemLogFile -Append
        "[*] Current User : $env:USERNAME" | Out-File -FilePath $localSystemLogFile -Append

        # enumerate all local users and identify enabled accounts
        $allUsers = @(Get-LocalUser | select Name, Enabled)
        '[*] Local User Accounts' | Out-File $localSystemLogFile -Append
        foreach ($user in $allUsers){
            "`t"+$user.Name + " : Enabled - " + $user.Enabled | Out-File -FilePath $localSystemLogFile -Append
    
        }
        # list all users home directories and their contents which are accessible and save to log
        '[*] Local Users Home Directory Contents' | Out-File -FilePath $localSystemLogFile -Append
        Get-ChildItem -Path C:\Users\$allUsers -Recurse -OutVariable userFolders
        $userFolders | Out-File -FilePath $localSystemLogFile -Append
        
        # enumerate all local groups
        '[*] Local Groups' | Out-File -FilePath $localSystemLogFile -Append
        $localGroups = Get-LocalGroup
        foreach ($group in $localGroups){
            "`t`t$group" | Out-File -FilePath $localSystemLogFile -Append
        }
        # enumerate local administrators group
        $localAdmins = @(Get-LocalGroupMember -Name 'Administrators')
        '[*] Local Administrators' | Out-File -FilePath $localSystemLogFile -Append
        foreach ($admin in $localAdmins){
            "`t`t$admin" | Out-File -FilePath $localSystemLogFile -Append
        }

        pause
    }

    elseif ($selection -eq 'B'){
        # enumerate operating system
        Write-Host 'Enumerating operating system'
        '--- Operating System ---' | Out-File -FilePath $localSystemLogFile -Append
        "[*] Computer Name : $env:COMPUTERNAME" | Out-File -FilePath $localSystemLogFile -Append

        # enumeating OS details
        $operatingSystemName = (Get-WmiObject Win32_OperatingSystem).Caption
        $operatingSystemVersion = (Get-WmiObject Win32_OperatingSystem).Version
        $operatingSystemBuild = (Get-WmiObject Win32_OperatingSystem).BuildNumber
        $operatingSystemArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
        '[*] Operating System Details' | Out-File -FilePath $localSystemLogFile -Append
        "`tName : $operatingSystemName" | Out-File -FilePath $localSystemLogFile -Append
        "`tVersion : $operatingSystemVersion" | Out-File -FilePath $localSystemLogFile -Append
        "`tBuild : $operatingSystemBuild" | Out-File -FilePath $localSystemLogFile -Append
        "`t$operatingSystemArchitecture" | Out-File -FilePath $localSystemLogFile -Append
   
        # enumerate hotfix and installed software
        # installed hotfixes
        '[*] Installed Hotfixes and Software' | Out-File -FilePath $localSystemLogFile -Append
        "`tHotfixes`n" | Out-File -FilePath $localSystemLogFile -Append
        (Get-HotFix -ComputerName $env:COMPUTERNAME) | Out-File -FilePath $localSystemLogFile -Append
        # installed software
        "`tSoftware Packages`n" | Out-File -FilePath $localSystemLogFile -Append
        Get-WMIObject -Query "SELECT * FROM Win32_Product" | FT Name, Vendor, Version, Caption | Out-File -FilePath $localSystemLogFile -Append

        # running services
        '[*]Active Running Services' | Out-File -FilePath $localSystemLogFile -Append
        Get-Service | Where-Object {$_.Status -eq "Running"} | select Name, DisplayName | Out-File -FilePath $localSystemLogFile -Append

        # check for unquoted service paths
        #TODO
        pause
    }

    elseif ($selection -eq 'C'){
        # enumerate network
        Write-Host 'Enumerating network configuration'
        '--- Network Configuration ---' | Out-File -FilePath $localSystemLogFile -Append
        # enumerate IP v4 addresses
        $ipV4AddressList = (Get-NetIPAddress | Where-Object { $_.IPv4Address -ne $null }).IPv4Address
        '[*] IP v4 Addresses' | Out-File -FilePath $localSystemLogFile -Append
        foreach ($ipv4Address in $ipV4AddressList){
            "`t$ipV4Address" | Out-File -FilePath $localSystemLogFile -Append
        }

        # enumerate IP v6 addresses
        $ipV6AddressList = (Get-NetIPAddress | Where-Object { $_.IPv6Address -ne $null }).IPv6Address
        '[*] IP v6 Addresses' | Out-File -FilePath $localSystemLogFile -Append
        foreach ($ipv6Address in $ipV6AddressList){
            "`t$ipV6Address" | Out-File -FilePath $localSystemLogFile -Append
        }

        # enumerate routing table
        '[*] IP Routing' | Out-File -FilePath $localSystemLogFile -Append
        Get-NetRoute | Out-File -FilePath $localSystemLogFile -Append

        # enumerate listening and establed tcp / udp connections
        '[*] TCP and UDP Ports' | Out-File -FilePath $localSystemLogFile -Append
        Get-NetTcpConnection -State Listen, Established | Out-File -FilePath $localSystemLogFile -Append
        Get-NetUDPEndpoint | Out-File -FilePath $localSystemLogFile -Append
        
        # output results
        Write-Host "[*] Network configuration written to`n`t$localSystemLogFile"
        # enumerate firewall rules
        '[*] Firewall rules'| Out-File -FilePath $firewallLog -Append
        "`tInbound Firewall rules" | Out-File -FilePath $firewallLog -Append
        Get-NetFirewallRule | Where { $_.Enabled –eq ‘True’ –and $_.Direction –eq ‘Inbound’} | Out-File -FilePath $firewallLog -Append
        "`tOutbound Firewall rules" | Out-File -FilePath $firewallLog -Append
        Get-NetFirewallRule | Where { $_.Enabled –eq ‘True’ –and $_.Direction –eq ‘Outbound’} | Out-File -FilePath $firewallLog -Append
        Write-Host "[*] Firewall rules written to`n`t$firewallLog"

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
                    "[+] $key Contains $searchTerm" | Out-File -FilePath $registryLog -Append
                }
            }
        }
        Write-Host "[*] Registry search results written to`n`t$registryLog"
        pause
    }

    else{ # this shouldn't be reachable
        # exit Enumerate-LocalSystem function
        return
    }
}
# end local system enumeration function

# domain enumeration
function Enumerate-Domain{
    param(
        [Parameter(Position=0,mandatory=$true)][string]$selection
        )
    Clear-Host
    if ($selection -eq 'A'){
        # enumerate domain details
        Write-Host 'Enumerating domain'
        # get domain name
        "[*} Domain Name : $env:USERDNSDOMAIN" | Out-File -FilePath $domainLogFile -Append

        # get the domain SID
        Write-Host 'Getting domain SID'
        $userName = $env:USERNAME
        $user = New-Object System.Security.Principal.NTAccount($username)
        $sid = $user.Translate([System.Security.Principal.SecurityIdentifier])
        $userSid = $sid.Value
        $domainSidValues = @($userSid.Split("-")[0..6])
        $domainSid = $domainSidValues -join '-'
        "[*] Domain SID : $domainSid" | Out-File -FilePath $domainLogFile -Append

        # locate all domain controllers in the forest
        Write-Host 'Searching forest for domain controllers'
        '[*] Domain Controllers' | Out-File -FilePath $domainLogFile -Append
        $forest = [System.Directoryservices.ActiveDirectory.Forest]::GetCurrentForest()  
        $forest.Domains | ForEach-Object {$_.DomainControllers} |`
        ForEach-Object {
            $hostEntry= [System.Net.Dns]::GetHostByName($_.Name)
            New-Object -TypeName PSObject -Property @{
                Name = $_.Name
                IPAddress = $hostEntry.AddressList[0].IPAddressToString
            }
        }`
        | Select Name, IPAddress | Out-File -FilePath $domainLogFile -Append

        # enumerate domain joined computers
        '[*] Domain Computers' | Out-File -FilePath $domainLogFile -Append
        Get-DomainObject('Computer')
    } 
    elseif ($selection -eq 'B'){
        # enumerate domain users and groups
        "`n[*] Domain Users" | Out-File -FilePath $domainLogFile -Append
        Get-DomainObject('User')
        "`n[*] Domain Groups" | Out-File -FilePath $domainLogFile -Append
        Get-DomainObject('Group')
        
    }
    elseif ($selection -eq 'C'){
        #enumerate domain shares
        #TODO
    }
    else{ # this shouldn't be reachable
        # exit Enumerate-Domain function
        return
    }
}
# end domain enumeration function

# start domain object search function
function Get-DomainObject{
    param(
        [Parameter(Position=0,mandatory=$true)][string]$domainObject
        )
        $objectTypes = @('User','Group','Computer')
        if ($domainObject | Where-Object { $_ -in $objectTypes }){
            $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
            $domainList = @($forest.Domains)
            $domains = $domainList | foreach { $_.name }
            foreach ($domain in $domains)
            {
                $strFilter = "(objectCategory=$domainObject)"
                $objDomain = New-Object System.DirectoryServices.DirectoryEntry
                $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
                $objSearcher.SearchRoot = $objDomain
                $objSearcher.PageSize = 10000
                $objSearcher.Filter = $strFilter
                $objSearcher.SearchScope = "Subtree"
                $colProplist = "name", "samaccountname"
                foreach ($i in $colPropList)
                {
                    $objSearcher.PropertiesToLoad.Add($i)
                }
                $colResults = $objSearcher.FindAll()
                $colResults
                foreach ($objResult in $colResults){
                    "`tsAMAccountName: " + $objResult.Properties.samaccountname | Out-File -FilePath $domainLogFile -Append
                }
            }
        }
        else{
            break #either a User or Computer object should be passed each time
        }


}
# end domain object search function

# enumerate all function
    # create an array holding all valid options for Enumerate-LocalSystem and Enumerate-Domain
    # loop through the array executing each option
    #$domainMenuArray = @('A','B','C')
    #foreach ($value in $domainMenuArray){ Write-Host $value} execute function calls
# end enumerate all function

# execute program
# log file locations (keeping things seperate to make life easier)
$localSystemLogFile = ${env:USERPROFILE} + "\Documents\$(Get-Date -Format 'yyyy-MM-dd')_WE_localSystemLog.txt"
$firewallLog = ${env:USERPROFILE} + "\Documents\$(Get-Date -Format 'yyyy-MM-dd')_WE_firewall_log.txt"
$registryLog = ${env:USERPROFILE} + "\Documents\$(Get-Date -Format 'yyyy-MM-dd')_WE_registry_log.txt"
$domainLogFile = ${env:USERPROFILE} + "\Documents\$(Get-Date -Format 'yyyy-MM-dd')_WE_DomainDetailsLog.txt"
Show-MainMenu
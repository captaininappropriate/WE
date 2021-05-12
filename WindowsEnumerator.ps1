# Name        : Windows Enumerator
# Author      : Greg Nimmo
# Version     : 0.1
# Description : Post exploitation script to automate common enumeration activities within a Windows envrionment

# start menu functions
# main menu function
function Show-MainMenu {
    param (
        [string]$title = 'Windows Enumerator'
    )
    Clear-Host
    Write-Host "`n========== $title =========="
    Write-Host "`t 'A' Local system enumeration"
    Write-Host "`t 'B' Domain enumeration"
    Write-Host "`t 'Q to Quit'"
    Write-Host "================================="
}
# local system submenu function 
function Show-LocalSystemSubneMenu {
    param (
        [string]$title = 'Local System Enumeration'
    )
    Clear-Host
    Write-Host "`n========== $title =========="
    Write-Host "`t 'A' Accounts"
    Write-Host "`t 'B' Operating System"
    Write-Host "`t 'C' Network"
    Write-Host "`t 'Q to Quit'"
    Write-Host "================================================"
} 

# domain enumeration submenu function
function Show-DomainSubMenu {
    param (
        [string]$title = 'Domain Enumeration'
    )
    Clear-Host
    Write-Host "`n========== $title =========="
    Write-Host "`t 'A' Domain Details"
    Write-Host "`t 'B' Domain Objects"
    Write-Host "`t 'Q to Quit'"
    Write-Host "=========================================="
}

# end menu functions

# start enumeration functions
function Enum-Accounts {
    param (
        [string]$title = 'Account enumeration'
    )
    Clear-Host 
    Write-Host 'Gathering local system account information'
    $userName = $env:USERNAME # current sessiion context
    $computerName = $env:COMPUTERNAME # computer name

}


# end enumeration functions

# main program body
# start main do loop
do {
    Show-MainMenu
    $mainMenuSelection = Read-Host "`tEnter your selection"
    
    switch ($mainMenuSelection) {
    'A'{
        Show-LocalSystemSubneMenu

        # until the user quits the menu
        }
    'B'{
        Show-DomainSubMenu
        pause # debug
        # do stuff 
        }
     } # end switch

} until ($mainMenuSelection -eq 'Q') # end main do



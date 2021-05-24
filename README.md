Windows Enumerator (WE) A tool for automating common enumeration activities within a Windows environment 

This was written to be used on any Windows computer with PowerShell and as such does not require the RSAT Active Directory module for PowerShell
TODO: 
    - search for unquoted service paths
    - extend registry search capabilities
    - add enumerate all functionality

Gathers the follow information:

- [ ] Domain
    - [ ] Domain name and SID
    - [ ] Domain controllers
    - [ ] Domain objects 
        - [ ] Domain users
        - [ ] Domain groups 
            - [ ] All *Admin* domain groups
        - [ ] Domain computers
            - [ ] Domain computer shares

- [ ] Local system
    - [ ] Accounts
        - [ ] Local users
	- [ ] Users files and directories
        - [ ] Local groups
            - [ ] Local administrators 
    - [ ] Operating system 
        - [ ] Version 
        - [ ] Patch level
        - [ ] Installed applications
        - [ ] Services
    - [ ] Network 
        - [ ] IP address and subnet 
	- [ ] Routing table 
        - [ ] Open ports
            - [ ] Local only listeners 
            - [ ] Remote only listeners
        - [ ] Firewall rules
            - [ ] Inbound 
            - [ ] Outbound 
    - [ ] Registry Keys

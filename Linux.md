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

**Weak File Permissions**

**SSH Keys**

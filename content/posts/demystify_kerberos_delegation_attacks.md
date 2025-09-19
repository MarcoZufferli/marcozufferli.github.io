---
title: "Demystify Kerberos Delegation Attacks"
date: 2025-09-16T14:56:19+02:00
draft: true
toc: false
---
---
#### Table of Contents:
- Abuse Unconstrained Delegation
    - Abuse Unconstrained Delegation (Computer) (1 method) - Windows
    - Abuse Unconstrained Delegation (Computer) (2 method) - Windows
    - Abuse Unconstrained Delegation - Detect & Mitigation
- [Abuse Protocol Transition](#abuse-protocol-transition)
    - [Abuse Protocol Transition (Computer) - Windows](#abuse-protocol-transition-computer---windows)
    - [Abuse Protocol Transition (User) - Windows](#abuse-protocol-transition-user---windows)
    - Abuse Protocol Transition (Computer)- Linux
    - Abuse Protocol Transition (User) - Linux
    - Abuse Protocol Transition - Detect & Mitigation
- [Abuse RBCD via DACL](#abuse-rbcd-via-dacl)
    - [Abuse RBCD via DACL (Computer) - Windows](#abuse-rbcd-via-dacl-computer---windows)
    - Abuse RBCD via DACL (Computer) - Linux
    - Abuse RBCD via DACL - Detect & Mitigation
- Abuse Kerberos Only
    - Abuse Kerberos Only (Computer) - Windows
    - Abuse Kerberos Only (User) - Windows
    - Abuse Kerberos Only - Detect & Mitigation
---

# **Kerberos Delegation Attacks**

{{< image src="/demystify_kerberos_delegation_attacks/immagine.png" position="center" style="border-radius: 8px;">}}

## **Let's start with the Kerberos Delegation Attacks!**

Before you begin, if you are not confident with Kerberos Delegation, i highly suggest you to start reading my other article called "[Demystify Kerberos Delegation](./demystify_kerberos_delegation.md)".

In this article i'll describe the most common abuse about Kerberos Delegation, specificaly, my home lab ([>= 2021](./demystify_kerberos_delegation.md#behaviour-change-about-kerberos-delegation-on-modern-windows-system)) is build with:

- 1 Domain Controller: Windows Server 2022 ([fresh installation](https://www.microsoft.com/it-it/evalcenter/download-windows-server-2022))
- 2 Windows Client: Windows 10 ([fresh installation](https://www.microsoft.com/it-it/evalcenter/download-windows-10-enterprise))

So, let's start!

## **Abuse Protocol Transition**

If an attacker compromises a Service Account with "[Constrained Delegation (Use any authentication Protocol)](./demystify_kerberos_delegation.md#constrained-delegation-use-any-authentication-protocol--protocol-transition)" enabled (a.k.a Protocol Transition), so, in most scenarios a Computer Account (usually by compromising the corresponding machine), the attacker, by impersonating the machine, could invoke the ["S4U2Self" & "S4U2Proxy"](./demystify_kerberos_delegation.md#100) extensions and thus obtain a TGS Ticket belonging to a certain user valid to access the Back-End service that the compromised machine is authorized to access on behalf of the Client (so the services indicated in the "[msds-allowedtodelegateto](./demystify_kerberos_delegation.md#101)" flag).

That said, there are two other extremely useful pieces of information to consider:

1. [As already mentioned](./demystify_kerberos_delegation.md#31), when the [S4U2Self](./demystify_kerberos_delegation.md#2-krb_tgs_req-s4u2self--s4uself-request) extension is invoked, it is necessary to specify which domain user will be the owner of the TGS Ticket that will be issued, in this step i want to highlight that the KDC will performs NO checks about that so it will issue the TGS Ticket for ANY specified domain user.

    Knowing this the attacker can invoke the [S4U2Self](./demystify_kerberos_delegation.md#2-krb_tgs_req-s4u2self--s4uself-request) extension for ANY domain user and thus obtain a TGS Ticket belonging to an arbitrary domain user, so the attacker will be able to authenticate to the Back-End service impersonating ANY domain user.
<span id=4>

2. The TGS Ticket always consists of two parts: a NON encrypted part containing the SPN of the requested service (e.g: CIFS/WORKSTATION01) and an "encrypted" part containing other information.

    Since the SPN contained in the TGS Ticket is NOT encrypted, an attacker could modify it (it would still be a valid TGS Ticket) by replacing the service of the target machine with another service also exposed on the target machine, thus, an attacker could for example obtain a valid TGS Ticket for the CIFS service on the SQL01 machine (CIFS\SQL01) and modify it to make it valid for the HTTP service on the same SQL01 machine (HTTP/SQL01) before sending it in a KRB\_AP\_REQ.

<span id=1>

> The service that is inserted must have the same Service Account as the replaced service (since the Service Account is often the Computer Account this requirement will be usually satisfied - [because the Computer Account is the Service Account in the Kerberos context of ANY service running under the LocalSystem account, including usually CIFS, HTTP, etc; so a lot of services](./not_so_brief_overview_about_kerberos.md#17)), only in this way will the TGS Ticket with the modified SPN be valid.

With this information in mind we figure out the following conclusion:

**If an attacker compromises a Service Account with "[Constrained Delegation (Use any authentication Protocol)](./demystify_kerberos_delegation.md#constrained-delegation-use-any-authentication-protocol--protocol-transition)" enabled (a.k.a Protocol Transition), so, in most scenarios a Computer Account (usually by compromising the related machine), the attacker impersonating the machine could invoke the ["S4U2Self" & "S4U2Proxy"](./demystify_kerberos_delegation.md#100) extension and thus obtain a TGS Ticket belonging to ANY domain user and valid to access ANY ([usually](#1)) Back-End service that the compromised machine is authorized to access on behalf of the Client (indicated in the "[msds-allowedtodelegateto](./demystify_kerberos_delegation.md#101)" flag).**

By exploiting this attack, the attacker will therefore be able to authenticate with administrative privileges (since they can impersonate ANY domain user) to certain services; depending on the type of service accessed, the attacker could perform [various malicious activities](https://zer1t0.gitlab.io/posts/attacking_ad/#s4u-attacks), for example:

- **LDAP on a Domain Controller**: As described by Microsoft ([1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/06205d97-30da-4fdc-a276-3fd831b272e0), [2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/0597aff6-0177-4d52-99f2-14a5441bc3c1)), some functionalities provided by the MDRS protocol (the protocol used to perform a DC Sync Attack) are also accessible via the LDAP protocol; this overlap of functionalities, broadly speaking, allows an attacker who obtains a valid TGS Ticket for the LDAP service (impersonating an administrative user, e.g., Domain Admin) to perform a [DC Sync Attack](https://adsecurity.org/?p=1729) against the DC.

> I don’t fully understand how this happens under-the-hood; sniffing with Wireshark shows that the LDAP service is not actually queried, instead, packet exchanges occur exclusively with the services used by the MDRS protocol.

- **SMB**: If the attacker impersonates an administrative user (e.g., Domain Admin) to the SMB service (CIFS in SPN context) of a computer, the attacker could authenticate using tools like "psexec" (depending on the PsExec tool used, it will impersonate the LocalSystem / Local Administrator user).

- **MSSQL**: If the attacker impersonates an administrative user (e.g., Domain Admin) to the MSSQL service, the attacker, in addition to potentially obtaining sensitive data contained within, can exploit the MSSQL service to execute local commands on the machine via "xp\_cmdshell,", use "[SQL Server Link](https://www.netspi.com/blog/technical-blog/network-pentesting/sql-server-link-crawling-powerupsql/)" and etc.

- **HTTP**: Since the [WinRM](https://blog.scalefusion.com/it/windows-remote-management-guide/) service uses the HTTP service, if the attacker impersonates an administrative user (e.g., Domain Admin) to the HTTP service of a computer, and the machine has WinRM enabled, the attacker could authenticate to it.

> Often an error related to [a missing "Logon Session" occurs](https://sensepost.com/blog/2022/constrained-delegation-considerations-for-lateral-movement/); in that case, retry the attack ensuring that the command exploiting Kerberos Delegation is executed from a shell with a High Integrity Level Token and that no additional Tickets have been previously injected into that Logon Session; after that, try logging in both via PowerShell Remoting (Enter-PSSession, New-PSSession, and Invoke-Command) and WinRS; using this method, logging in usually succeeds.

**In conclusion, broadly speaking, if an attacker compromises a machine (or a domain user acting as a Service Account) with "Constrained Delegation (Use any authentication Protocol)" enabled, they can also compromise the machine (usually via CIFS) that the compromised system is authorized (via the "msds-allowedtodelegateto" flag) to access on behalf of the Client.**

## **Abuse Protocol Transition (Computer) - Windows**

In this scenario, we will see how to exploit a **Constrained Delegation (Use any authentication Protocol) (also called Protocol Transition)** from a Windows machine.

1. **Identify which Service Accounts have "Constrained Delegation (Use any authentication Protocol)" enabled (in this scenario, we are looking for Computer Accounts acting as Service Accounts).**

    There are different methods to identify which Service Accounts have "Constrained Delegation (Use any authentication Protocol)"; on Windows, one of the most common is using "PowerView":

    *PS C:> Get-DomainComputer --TrustedToAuth*
    <span id=2>

    {{< image src="/demystify_kerberos_delegation_attacks/1.png" position="center" style="border-radius: 8px;">}}

    As you can see, the Computer Account THEPUNISHER\$ has the "[TRUSTED\_TO\_AUTH\_FOR\_DELEGATION](./demystify_kerberos_delegation.md#102)" flag and therefore has [Constrained Delegation (Use any authentication Protocol)](./demystify_kerberos_delegation.md#constrained-delegation-use-any-authentication-protocol--protocol-transition) enabled; specifically, this account (so THEPUNISHER$) and therefore ALL services running under it will be able to authenticate on behalf of the Client exclusively to the SPN "HTTP/SPIDERMAN," so to the HTTP service of the SPIDERMAN machine.

    Indeed, inspecting the "Delegation" tab of the THEPUNISHER computer via ADUC, we will find this     configuration.

    {{< image src="/demystify_kerberos_delegation_attacks/2.png" position="center" style="border-radius: 8px;">}}

2. **The attacker compromises the Service Account with Constrained Delegation (Use any authentication Protocol) enabled.**

    In this scenario, the attacker managed to authenticate with administrative privileges to the THEPUNISHER machine and, by dumping LSASS, obtained the credentials of the Computer Account THEPUNISHER\$, so the Service Account with the Constrained Delegation (Use any authentication Protocol) enabled.

    {{< image src="/demystify_kerberos_delegation_attacks/3.png" position="center" style="border-radius: 8px;">}}

3. **The attacker obtains a valid TGS Ticket (for Domain Admin) to authenticate to the CIFS service hosted on the SPIDERMAN machine (that is, the machine authorized in the "msds-allowedtodelegateto" flag).**

    The attacker, now possessing the credentials of the Service Account THEPUNISHER\$, since this account has "Constrained Delegation (Use any authentication Protocol)", can abuse it to invoke the S4U2Self & S4U2Proxy extensions and thus obtain a TGS Ticket belonging to a Domain Admin user valid to access the HTTP service of the SPIDERMAN machine ([so, the service specified in the "msds-allowedtodelegateto" flag](#2)); furthermore, in this scenario the attacker decides to replace the SPN "HTTP/SPIDERMAN" with the SPN "CIFS/SPIDERMAN", managing in this way to authenticate via PsExec to the SPIDERMAN machine.

    Since we will inject the desired TGS Ticket into memory, first of all we use the so-called Sacrificial Process.

    *C:> Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show*

    {{< image src="/demystify_kerberos_delegation_attacks/4.png" position="center" style="border-radius: 8px;">}}

    Then execute the following Rubeus command within the Sacrificial Process.
    <span id=5>
   
    *C:> Rubeus.exe s4u /impersonateuser:\<User\_To\_Impersonate> /msdsspn:\<SPN\_content\_in\_msds-allowedtodelegateto> /altservice:\<Desired\_SPN> /user:\<Service\_Account> /rc4:\<NTHash\_Service\_Account> /nowrap /ptt*

    Let's analyze ALL the operations performed by Rubeus.

    1. **Rubeus sent a "[KRB\_AS\_REQ](./not_so_brief_overview_about_kerberos.md#39)" to obtain the TGT Ticket of the Computer Account THEPUNISHER\$, [information necessary](./demystify_kerberos_delegation.md#109) to invoke the "KRB\_TGS\_REQ (S4USelf)".**
      
       <!-- only for spacing -->
    
        {{< image src="/demystify_kerberos_delegation_attacks/5.png" position="center" style="border-radius: 8px;">}}
        <br>
        {{< image src="/demystify_kerberos_delegation_attacks/6.png" position="center" style="border-radius: 8px;">}}

    2. **Rubeus now, having the TGT Ticket of the Computer Account "THEPUNISHER\$", sends a "KRB\_TGS\_REQ [(S4U2Self)](./demystify_kerberos_delegation.md#2-krb_tgs_req-s4u2self--s4uself-request)" to obtain a TGS Ticket on behalf of the user "MARVEL\Administrator" (Domain Admin) valid for the service itself.**

       <!-- only for spacing -->
       
        {{< image src="/demystify_kerberos_delegation_attacks/7.png" position="center" style="border-radius: 8px;">}}
        
        As we can note Rubeus sends a "KRB\_TGS\_REQ [(S4U2Self)](./demystify_kerberos_delegation.md#2-krb_tgs_req-s4u2self--s4uself-request)", analyzing the packet content one can observe that: 1) [Inside the "PA-FOR-USER"](./demystify_kerberos_delegation.md#111) data structure the request for the TGS Ticket on behalf of the user "MARVEL\Administrator" (it's a Domain Admin) is effectively present 2) [The Computer Account THEPUNISHER\$ is expressly indicated](./demystify_kerberos_delegation.md#31), in this way the issued TGS Ticket will be valid for ALL services started by that Service Account.

        {{< image src="/demystify_kerberos_delegation_attacks/8.png" position="center" style="border-radius: 8px;">}}
        <span id=3>

        The KDC [verifies](./demystify_kerberos_delegation.md#112) that the Service Account THEPUNISHER\$ has the "[TRUSTED\_TO\_AUTH\_FOR\_DELEGATION](./demystify_kerberos_delegation.md#102)" flag, and since the result is [positive](#2), the KDC issues the requested TGS Ticket (which belong to the user MARVEL\Administrator" & is valid for ALL services started by that Service Account), furthermore, i remind you that such a TGS Ticket issued in this positive case will have the "FORWARDABLE" flag set to "1".

        {{< image src="/demystify_kerberos_delegation_attacks/9.png" position="center" style="border-radius: 8px;">}}

    3. **Rubeus now that it has the TGS Ticket (belonging to the user MARVEL\Administrator") valid for the service itself, will be able to use it as "evidence" to invoke the "KRB\_TGS\_REQ ([S4UProxy](./demystify_kerberos_delegation.md#118))", in this way the attacker will obtain a TGS Ticket (still belonging to the user MARVEL\Administrator") valid for the HTTP service exposed on the SPIDERMAN machine (HTTP/SPIDERMAN), finally, Rubeus will replace the HTTP service with the CIFS service, obtaining a TGS Ticket (still belonging to the user MARVEL\Administrator") valid for the CIFS service exposed on the SPIDERMAN machine.**

        {{< image src="/demystify_kerberos_delegation_attacks/10.png" position="center" style="border-radius: 8px;">}}
    
        As we can see Rubeus sends a "KRB\_TGS\_REQ ([S4UProxy](./demystify_kerberos_delegation.md#118)", analyzing the content of the packet it can be ascertained that: 1) Inside the "Additional Ticket" field the [TGS Ticket previously received in the "S4USelf Response" is indeed sent](#37) 2) The SPN that points to the service which the compromised machine (Computer Account THEPUNISHER\$) is authorized to access on behalf of the Client (indicated in the ["msds-allowedtodelegateto" flag](#2)) is indicated, in fact the SPN "HTTP/SPIDERMAN.MARVEL.local" is present

        {{< image src="/demystify_kerberos_delegation_attacks/11.png" position="center" style="border-radius: 8px;">}}

        The KDC [verifies](./demystify_kerberos_delegation.md#51) if the TGS Ticket received inside the "additional-tickets" field (in addition to being valid) has the "FORWARDABLE" flag set to "1" & that inside the "[msds-allowedtodelegateto flag](#2)" parameter of the Service Account THEPUNISHER\$ the requested service is present, (so is in this case "HTTP/SPIDERMAN.MARVEL.local"), since the outcome is positive for both checks ([1](#3), [2](#2)), the KDC issues a TGS Ticket (belonging to the user MARVEL\Administrator") valid for the HTTP service exposed on the SPIDERMAN machine (furthermore, as for any other valid TGS Ticket this one will also have the "FORWARDABLE" flag set to "1").

         {{< image src="/demystify_kerberos_delegation_attacks/12.png" position="center" style="border-radius: 8px;">}}

         Finally, Rubeus will [modify](#4) the SPN field of the received TGS Ticket, replacing the HTTP service with the desired CIFS service, in this way the output TGS Ticket (belonging to the user MARVEL\Administrator") will have as SPN "CIFS/SPIDERMAN" and will therefore be valid for the CIFS service exposed on the SPIDERMAN machine, having done this Rubeus imports that Kerberos Ticket into memory.

        > If the attacker does NOT wish to replace the service of the TGS Ticket obtained via S4UProxy they will simply NOT include the ["altservice" parameter](#5) on Rubeus command, consequently, in this context we will obtain a TGS Ticket (belonging to the user MARVEL\Administrator") valid for the HTTP service present on the SPIDERMAN machine.

As you can see, following the Rubeus command we will have cached in memory a TGS Ticket belonging to the "Administrator" user valid for the CIFS service of the SPIDERMAN machine; in fact, performing a Network Logon with "PsExec" the OS will retrieve the cached TGS Ticket and use it to perform the authentication; in this way the attacker has succeeded in authenticating with administrative permissions to the SPIDERMAN computer.

{{< image src="/demystify_kerberos_delegation_attacks/13.png" position="center" style="border-radius: 8px;">}}

> The LogonID in this screenshot is different from that of the Sacrificial Process previously indicated simply because i have repeated this lab infinite times.

>  If you encounter an authentication error, try re-running the command by adding the ["msdsspn" parameter](#5) with a value that does not include the domain suffix, changing from "SPIDERMAN.MARVEL.local" to "SPIDERMAN"; in both cases it should still work because [both values are present within the "msds-allowedtodelegateto" property](#2), additionally, ensure that the same domain naming used in "msdsspn" is applied in the PsExec command (in this case), so if, for example, you request a TGS Ticket to access the SPIDERMAN.MARVEL.local machine, use the same naming to connect via PsExec.

## **Abuse Protocol Transition (User) - Windows**

Although Kerberos Delegation is typically applied to a "Computer Account" type Service Account, it can, (although it's a rare configuration) also be applied to a "[User](https://learn.microsoft.com/en-us/windows/win32/ad/user-object-attributes)" type Service Account (a traditional domain user).

If we identify a "[User](https://learn.microsoft.com/en-us/windows/win32/ad/user-object-attributes)" type Service Account (a traditional domain user) with ["Constrained Delegation (Use any authentication Protocol)](./demystify_kerberos_delegation.md#constrained-delegation-use-any-authentication-protocol--protocol-transition)" enabled, it is possible to execute the [same steps previously seen](#abuse-protocol-transition-computer---windows) to abuse this configuration.

In other words, if an attacker compromises a domain user acting as a Service Account and has "[Constrained Delegation (Use any authentication Protocol)](./demystify_kerberos_delegation.md#constrained-delegation-use-any-authentication-protocol--protocol-transition)" enabled, the attacker, impersonating this Service Account (domain user), could invoke the ["S4U2Self" & "S4U2Proxy"](./demystify_kerberos_delegation.md#100) extensions and thereby obtain a TGS Ticket belonging to ANY domain user and valid to access ANY ([usually](#1)) Back-End service for which the Service Account (domain user) has authorization to access on behalf of the Client (as indicated in the "[msds-allowedtodelegateto](./demystify_kerberos_delegation.md#101)" flag).

**To save both my and your lifetime, instead of re-executing ALL the following steps as previously done, i will report only the essential steps:**

1. **Identify which Service Accounts have "Constrained Delegation (Use any authentication Protocol)" enabled (in this scenario, we are looking for a "User" type object, so a traditional domain user acting as a Service Account).**
    <span id=6>

    *PS C:\> Get-DomainUser --TrustedToAuth*

    {{< image src="/demystify_kerberos_delegation_attacks/14.png" position="center" style="border-radius: 8px;">}}

    As you can see, the "User" (traditional domain user) delegationuser has the "TRUSTED\_TO\_AUTH\_FOR\_DELEGATION" flag and therefore has Constrained Delegation (Use any authentication Protocol) enabled; specifically, this user (so "delegationuser") and therefore ALL services started with it (in this case the "delegationuser" Service Account has the SPN LDAP/WORKSTATION01 so it will run only the LDAP service on that machine) will be able to authenticate on behalf of the Client exclusively to the SPN "HTTP/SPIDERMAN", so, to the HTTP service of the SPIDERMAN machine.

    Indeed, inspecting the "Delegation" tab of the "User" delegationuser via ADUC, you will find this configuration.

    {{< image src="/demystify_kerberos_delegation_attacks/15.png" position="center" style="border-radius: 8px;">}}
    <br>
    {{< image src="/demystify_kerberos_delegation_attacks/16.png" position="center" style="border-radius: 8px;">}}

2. **The attacker compromises the Service Account with Constrained Delegation (Use any authentication Protocol) enabled.**

    In this scenario, the attacker has managed to obtain, for example via Password Spray, the credentials of the "delegationuser" account, so the Service Account with Constrained Delegation (Use any authentication Protocol) enabled.
    
3. **The attacker obtains a TGS Ticket (of a Domain Admin) valid to authenticate to the CIFS service hosted on the SPIDERMAN machine (that is, the machine authorized in the "[msds-allowedtodelegateto" flag](#6)).**

    The attacker, now possessing the credentials of the "delegateduser" Service Account, since it has "Constrained Delegation (Use any authentication Protocol)", can abuse it to invoke the S4U2Self & S4U2Proxy extensions and thus obtain a TGS Ticket belonging to a Domain Admin user valid to access the HTTP service of the SPIDERMAN machine ([so, the service specified by "msds-allowedtodelegateto" flag](#6)); furthermore, in this scenario, the attacker decides to replace the SPN "HTTP/SPIDERMAN" with the SPN "CIFS/SPIDERMAN", managing in this way to authenticate via PsExec to the SPIDERMAN machine.

    Since we will inject the desired TGS Ticket into memory, we first use the socalled Sacrificial Process, then execute the following Rubeus command within the Sacrificial Process.

    *C:\> Rubeus.exe s4u /impersonateuser:<User_To_Impersonate> /msdsspn:<SPN_contenuto_in_msds-allowedtodelegateto> /altservice:<SPN_desiderato> /user:<Service_Account> /rc4:<NTHash_Service_Account> /nowrap /ptt*

Let’s analyze in summary all the operations performed by Rubeus.

1) **Rubeus sent a "KRB\_AS\_REQ" to obtain the TGT of the Service Account (domain user) delegateduser, information necessary to invoke the "KRB\_TGS\_REQ (S4USelf)" (it happens regardless of whether the Service Account is a Computer Account or a traditional domain user).**

    {{< image src="/demystify_kerberos_delegation_attacks/17.png" position="center" style="border-radius: 8px;">}}

2) **Rubeus now, having the TGT Ticket of the "User" delegationuser, sends a "KRB\_TGS\_REQ (S4USelf)" to obtain a TGS Ticket on behalf of the "MARVEL\Administrator" user (Domain Admin) valid for the service itself.**

    {{< image src="/demystify_kerberos_delegation_attacks/18.png" position="center" style="border-radius: 8px;">}}

3) **Rubeus now that it has the TGS Ticket (belonging to the "MARVEL\Administrator" user) valid for the service itself, will be able to use it as "evidence" to invoke the "KRB\_TGS\_REQ (S4UProxy)"; in this way the attacker obtains a TGS Ticket (still belonging to the "MARVEL\Administrator" user) valid for the HTTP service exposed on the SPIDERMAN machine (HTTP/SPIDERMAN), finally, Rubeus will replace the HTTP service with the CIFS service, obtaining a TGS Ticket (still belonging to the "MARVEL\Administrator" user) valid for the CIFS service exposed on the SPIDERMAN machine.**

    {{< image src="/demystify_kerberos_delegation_attacks/19.png" position="center" style="border-radius: 8px;">}}

As you can see, following the Rubeus command we will have cached in memory a TGS Ticket belonging to the "Administrator" user valid for the CIFS service of the SPIDERMAN machine; in fact, when performing a Network Logon with "PsExec" the OS will retrieve the cached TGS Ticket and use it for authentication; in this way, the attacker has successfully authenticated with administrative privileges to the SPIDERMAN machine.

{{< image src="/demystify_kerberos_delegation_attacks/20.png" position="center" style="border-radius: 8px;">}}

## **Abuse RBCD via DACL**

Several techniques exist to exploit RBCD, below we will analyze by far the most common.

Since the trigger of a "Resource Based Constrained Delegation (RBCD)" is based on "[ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-allowedtoactonbehalfofotheridentity?ref=labs.lares.com)", which is nothing more than a property of a "Secureable Objects", [if the attacker has write permissions on this property (e.g: GenericalAll, GenericWrite and so on)](./demystify_kerberos_delegation.md#123), they could exploit a DACL Misconfiguration to configure an RBCD on an arbitrary target and potentially compromise it.

> In summary, Active Directory contains [entities called "Objects"](https://www.windows-active-directory.com/active-directory-objects-list.html) (Computers, Users, OUs, GPOs, Files, etc.) which for the vast majority are "Secureable Objects".
>
>[Secureable Objects](https://learn.microsoft.com/en-us/windows/win32/secauthz/securable-objects) are resources protected through Access Control and each "Secureable Object" has a Security Descriptor containing a [DACL (Discretionary Access Control List) and a SACL (System Access Control list (SACL)](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists):
>
>* The DACL (it contain a series of ACE - Access Control Entries) manages who can do what.
>* The SACL (it contain a series of ACE - Access Control Entries) logs audit events.
>
> When a "Secureable Object" performs an action within Active Directory toward another "Secureable Object" , the Domain Controller (that manages the AD) inspects the DACL to determine permissions and, consequently, if the action is allowed. 
>
>So a "[DACL Misconfiguration](https://labs.lares.com/securing-active-directory-via-acls/)" is simply a DACL containing ACLs that grant excessive permissions which could allows potential attacks, like in this case 😉​

An attacker in order to abuse RBCD via DACL requires 2 mandatory elements:

1. The attacker (impersonating a "Computer Account" or a "Domain User") must have write permissions available (WriteProperty, Generic Write, Generic All, Write DACL, Write Owner, Own) on the attribute "[ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-allowedtoactonbehalfofotheridentity)" of an:

    - Object of type "Computer" (so the related Computer Account) 

    - Object type "Users" (a traditional "Domain User" - [must have an SPN set](./demystify_kerberos_delegation.md#130))
    
     In this way the attacker is able to configure an RBCD with an arbitrary value within the target's attribute.

> In my lab and i was not able to successfully compromise a "Users" Object.

2. The attacker needs to control an account that is capable of invoking the "S4USelf" and "S4UProxy" extensions in order to exploit the previously configured RBCD, this can be done with a:

    - "Computer Account": Any "Computer Account" is able to arbitrary invoke the "S4USelf" and "S4UProxy".
    <span id=7>

    - "Domain user": Any "User" with a SPN setted is able to arbitrary invoke the "S4USelf" and "S4UProxy (unless the "SPN-less" technique is used [1](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html) - [2](https://medium.com/@offsecdeer/a-practical-guide-to-rbcd-exploitation-a3f1a47267d5), using this technique the "Domain User" used will become unavailable, so it's better to avoid)

**If both conditions are satisfied, an attacker can arbitrarily configure a malicious RBCD on the target, enabling him/her to impersonate ANY domain user to ANY service executed by the service account for which the RBCD was configured.**

**The following scenario covers the most common case where an attacker is able to satisfy the condition previusly indicated:**

1) **The attacker (impersonating a "Domain User) has write permissions on the "ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity" attribute of an object of type Computer (so on the related Computer Account)**; in this way the attacker is able to configure on it an RBCD with an arbitrary value within the target attribute.

> The attack can be carried out regardless of whether the target "Computer" object already has Unconstrained / Constrained Delegation enabled, because the KDC, after checks performed on the Computer Account created by the attacker (which simulates the AP Front End service), will switch in any case to RBCD and therefore issue a TGS Ticket valid to authenticate to the service hosted on the target "Computer" object.

2) **An attacker usually uses a "Computer Account" to invoke the "S4USelf" and "S4UProxy" extensions to exploit the previously configured RBCD**; it happens because every existing Computer Account has by default an SPN configured and thus it can arbitray invoke the "S4USelf" and "S4UProxy" kerberos extension ([it's more uncommon the scenario that applies to a "Domain User"](#7))

    An attacker in order to compromise a "Computer Account" could:

   - Compromise a Computer and retrieve its related Computer Account
   - [NTLM Relay Attacks](https://www.fortalicesolutions.com/posts/hunting-resource-based-constrained-delegation-in-active-directory)
   - Create an arbitrary Computer Account.
	
> The domain has an attribute named "[MS-DS-Machine-Account-Quota](https://www.netspi.com/blog/technical-blog/network-penetration-testing/machineaccountquota-is-useful-sometimes/)" that governs how many Computer Accounts a non-privileged user (usually a Computer Account & a traditional domain user) can create within the domain; by default this value is 10.
>
> If the value of this attribute is >=1 an attacker could create an arbitrary Computer Account and use it to carry out the attack.

## **Abuse RBCD via DACL (Computer) - Windows**




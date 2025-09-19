---
title: "Demystify Kerberos Delegation Attacks"
date: 2025-09-16T14:56:19+02:00
draft: false
toc: false
---
---
#### Table of Contents:
- Abuse Unconstrained Delegation
    - Abuse Unconstrained Delegation (Computer) (1 method) - Windows
    - Abuse Unconstrained Delegation (Computer) (2 method) - Windows
    - Abuse Unconstrained Delegation - Detect & Mitigation
- Abuse Protocol Transition
    - Abuse Protocol Transition (Computer) - Windows
    - Abuse Protocol Transition (User) - Windows
    - Abuse Protocol Transition (Computer)- Linux
    - Abuse Protocol Transition (User) - Linux
    - Abuse Protocol Transition - Detect & Mitigation
- Abuse RBCD via DACL
    - Abuse RBCD via DACL (Computer) - Windows
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

In this article i'll describe the most common abuse about Kerberos Delegation, specificaly, my home lab is build with:

- 1 Domain Controller: Windows Server 2022 ([fresh installation](https://www.microsoft.com/it-it/evalcenter/download-windows-server-2022))
- 2 Windows Client: Windows 10 ([fresh installation](https://www.microsoft.com/it-it/evalcenter/download-windows-10-enterprise))

So, let's start!

## **Abuse Protocol Transition**

If an attacker compromises a Service Account with "[Constrained Delegation (Use any authentication Protocol)](./demystify_kerberos_delegation.md#constrained-delegation-use-any-authentication-protocol--protocol-transition)" enabled (a.k.a Protocol Transition), so, in most scenarios a Computer Account (usually by compromising the corresponding machine), the attacker, by impersonating the machine, could invoke the ["S4U2Self" & "S4U2Proxy"](./demystify_kerberos_delegation.md#100) extensions and thus obtain a TGS Ticket belonging to a certain user valid to access the Back-End service that the compromised machine is authorized to access on behalf of the Client (so the services indicated in the "[msds-allowedtodelegateto](./demystify_kerberos_delegation.md#101)" flag).

That said, there are two other extremely useful pieces of information to consider:

1. [As already mentioned](./demystify_kerberos_delegation.md#31), when the [S4U2Self](./demystify_kerberos_delegation.md#2-krb_tgs_req-s4u2self--s4uself-request) extension is invoked, it is necessary to specify which domain user will be the owner of the TGS Ticket that will be issued, in this step i want to highlight that the KDC will performs NO checks about that so it will issue the TGS Ticket for ANY specified domain user.

    Knowing this the attacker can invoke the [S4U2Self](./demystify_kerberos_delegation.md#2-krb_tgs_req-s4u2self--s4uself-request) extension for ANY domain user and thus obtain a TGS Ticket belonging to an arbitrary domain user, so the attacker will be able to authenticate to the Back-End service impersonating ANY domain user.

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

1. Identify which Service Accounts have "Constrained Delegation (Use any authentication Protocol)" enabled (in this scenario, we are looking for Computer Accounts acting as Service Accounts).

    There are different methods to identify which Service Accounts have "Constrained Delegation (Use any authentication Protocol)"; on Windows, one of the most common is using "PowerView":

    PS C:> Get-DomainComputer --TrustedToAuth
    <span id=2>

    {{< image src="/demystify_kerberos_delegation_attacks/1.png" position="center" style="border-radius: 8px;">}}

    As you can see, the Computer Account THEPUNISHER\$ has the "[TRUSTED\_TO\_AUTH\_FOR\_DELEGATION](./demystify_kerberos_delegation.md#102)" flag and therefore has [Constrained Delegation (Use any authentication Protocol)](./demystify_kerberos_delegation.md#constrained-delegation-use-any-authentication-protocol--protocol-transition) enabled; specifically, this account (so THEPUNISHER$) and therefore ALL services running under it will be able to authenticate on behalf of the Client exclusively to the SPN "HTTP/SPIDERMAN," so to the HTTP service of the SPIDERMAN machine.

    Indeed, inspecting the "Delegation" tab of the THEPUNISHER computer via ADUC, we will find this     configuration.

    {{< image src="/demystify_kerberos_delegation_attacks/2.png" position="center" style="border-radius: 8px;">}}

2. The attacker compromises the Service Account with Constrained Delegation (Use any authentication Protocol) enabled.

    In this scenario, the attacker managed to authenticate with administrative privileges to the THEPUNISHER machine and, by dumping LSASS, obtained the credentials of the Computer Account THEPUNISHER\$, so the Service Account with the Constrained Delegation (Use any authentication Protocol) enabled.

    {{< image src="/demystify_kerberos_delegation_attacks/3.png" position="center" style="border-radius: 8px;">}}

3. The attacker obtains a valid TGS Ticket (for Domain Admin) to authenticate to the CIFS service hosted on the SPIDERMAN machine (that is, the machine authorized in the "msds-allowedtodelegateto" flag).

    The attacker, now possessing the credentials of the Service Account THEPUNISHER\$, since this account has "Constrained Delegation (Use any authentication Protocol)", can abuse it to invoke the S4U2Self & S4U2Proxy extensions and thus obtain a TGS Ticket belonging to a Domain Admin user valid to access the HTTP service of the SPIDERMAN machine ([so, the service specified in the "msds-allowedtodelegateto" flag](#2)); furthermore, in this scenario the attacker decides to replace the SPN "HTTP/SPIDERMAN" with the SPN "CIFS/SPIDERMAN", managing in this way to authenticate via PsExec to the SPIDERMAN machine.

    Since we will inject the desired TGS Ticket into memory, first of all we use the so-called Sacrificial Process.

    C:> Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show

    {{< image src="/demystify_kerberos_delegation_attacks/4.png" position="center" style="border-radius: 8px;">}}

    Then execute the following Rubeus command within the Sacrificial Process.

    C:> Rubeus.exe s4u /impersonateuser:\<User\_To\_Impersonate> /msdsspn:\<SPN\_content\_in\_msds-allowedtodelegateto> /altservice:\<Desired\_SPN> /user:\<Service\_Account> /rc4:\<NTLM\_Service\_Account> /nowrap /ptt

    Let's analyze ALL the operations performed by Rubeus.

    1. Rubeus sent a "[KRB\_AS\_REQ](./not_so_brief_overview_about_kerberos.md#39)" to obtain the TGT Ticket of the Computer Account THEPUNISHER\$, information necessary to invoke the "KRB\_TGS\_REQ (S4USelf)"




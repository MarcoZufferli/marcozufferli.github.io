---
title: "Demystify Kerberos Delegation"
date: 2025-09-16T14:50:00+02:00
draft: true
toc: false
---
---
#### Table of Contents:
- **[What's Kerberos Delegation](#whats-kerberos-delegation)**
- **[Unconstrained Delegation](#unconstrained-delegation)**
- **[Constrained Delegation](#constrained-delegation)**
  - **[Constrained Delegation (Kerberos only)](#constrained-delegation-kerberos-only)**
  - **[Constrained Delegation (Use any authentication Protocol) / Protocol Transition](#constrained-delegation-use-any-authentication-protocol--protocol-transition)**
- **[Resource Based Constrained Delegation (RBCD)](#resource-based-constrained-delegation-rbcd)**
---

# **Kerberos Delegation**

{{< image src="/demystify_kerberos_delegation/immagine.jpg" position="center" style="border-radius: 8px;">}}

## **What's Kerberos Delegation?**

Before you begin, if you are not confident with Kerberos, i highly suggest you to start reading my other article called "[Not So Brief Overview about Kerberos](./not_so_brief_overview_about_kerberos.md)".

Let's assume a scenario where a domain user authenticates via Kerberos to a "Front-End" AP (service) such as a Web Application, which, to operate correctly, must interact with a "Back-End" AP (service) such as a Database or a File Server. 

In this scenario, when the domain user authenticated via Kerberos performs a particular action on the Web Application, the Web Application will need to authenticate to the Database to retrieve some personal user data, instead of creating (if possible) an application user with extremely specific permissions for the Web Application to use for the Back-End service (in this case the Database), the issue would be resolved if the Web Application itself were able to authenticate via Kerberos to the "Back-End" service on behalf of the user; in this way, access could be granted exclusively and automatically to a specific portion of data; the Kerberos protocol allows this behavior and this is called Kerberos Delegation.

We know that the domain user "ASTRO\Cosmo" will present a TGS Ticket ([KRB\_AP\_REP](./not_so_brief_overview_about_kerberos#37)) to authenticate to the Web Server, consequently, in a traditional Kerberos scenario, the Web Server CANNOT obtain a TGS Ticket on behalf of the domain user "ASTRO\Cosmo" to access the SQL Server service, because by design, the Web Server, not knowing the NT Hash (or a secrets) of the "ASTRO\Cosmo" account, CANNOT request a TGT ([KRB\_AS\_REQ](./not_so_brief_overview_about_kerberos#39)) from the KDC on behalf of the user to then exchange it for a TGS Ticket specific to the SQL Server service.

> The traditional TGS Ticket that the Web Server receives from the "ASTRO\Cosmo" user is valid exclusively for the Web Server service (as it will contain the SPN HTTP/Web-Server and not a potential SPN SQL\SQLServer).

Below is a diagram representing this situation:

{{< image src="/demystify_kerberos_delegation/1.png" position="center" style="border-radius: 8px;">}}

The "Kerberos Delegation" feature alters the traditional Kerberos authentication flow to allow the Web Server to authenticate to the Database service on behalf of the domain user.

There are 3 types of Kerberos Delegation:

- Unconstrained Delegation
- Constrained Delegation (1, 2)
- Resource-Based Constrained (RBCD) Delegation

I want to highlight that the Kerberos Delegation feature allows solving the "[Double Hop Problem](https://techcommunity.microsoft.com/blog/askds/understanding-kerberos-double-hop/395463)".

> In a internet-facing web services scenario, the user will generally NOT login via the Kerberos protocol to the Web Application, consequently the Web Application will necessarily need to authenticate to a potential Database using only an dedicated application user; furthermore, depending on the permissions and how it has been configured, the Web Application may have access to the database with administrative or limited permissions; in specific scenarios this could lead to issues.

## **Unconstrained Delegation**

The oldest and most dangerous version of Kerberos Delegation is the "Unconstrained Kerberos Delegation".

The "Unconstrained Kerberos Delegation", in summary, alters the Kerberos protocol by making the Client send to the AP Front End a "KRB\_AP\_REQ" packet containing both the TGS Ticket (to access the same AP Front-End that receives this packet) and the TGT Ticket, in this way the "Front-End" AP will be able to use the domain user’s TGT Ticket to impersonate it in a further Kerberos authentication towards potentially ANY AP in the "Back-End".

{{< image src="/demystify_kerberos_delegation/2.png" position="center" style="border-radius: 8px;">}}

The KDC, in order to use the "Unconstrained Kerberos Delegation", requires 2 prerequisites:

**1. Configure the "Unconstrained Kerberos Delegation" on the "Front-End" AP.**

<span id =1>{{< image src="/demystify_kerberos_delegation/3.png" position="center" style="border-radius: 8px;">}}
  
  The "Unconstrained Kerberos Delegation" is configured via [ADUC](https://serveracademy.com/blog/active-directory-users-and-computers-aduc-installation-and-tutorial/) by enabling the property "Trust this computer for delegation to any service (Kerberos only)" on the "Computer" object that acts as the "Front-End" AP; since this configuration is potentially dangerous, such action can only be performed by a Domain Admin account or an account with the "[SeEnableDelegationPrivilege](https://harmj4.rssing.com/chan-30881824/article60.html)" permission.

  > In reality, even an object of type "user" (domain account) can be configured with the Kerberos Unconstrained Delegation, in this way such domain account will be able to impersonate another domain account to authenticate against target APs (services), however, to do this it is necessary that such account has at least 1 SPN configured, in fact only in this specific case the "Delegation" tab will appear inside the property of the user object.

  <span id=25> This configuration sets in the "UserAccountControl" property of the object in question the flag "TRUSTED\_FOR\_DELEGATION" to "TRUE" / "1".

> <span id=11>Every object of type "User" and type "Computer" has an attribute called "[UserAccountControl](https://activedirectorypro.com/useraccountcontrol-check-and-manage-attribute-value/)", this attribute is a value that represents the set of [flags](https://learn.microsoft.com/en-us/windows/win32/adschema/a-useraccountcontrol?redirectedfrom=MSDN) (configurations) set on the object (the most common are DONT\_REQUIRE\_PREAUTH, NOT\_DELEGATE, etc.), for example 514 indicates that the domain user is disabled.

  In our [example](#1) the Kerberos Delegation is configured on the Computer "THEPUNISHER" which will act as the "Front-End" AP, this modification is actually reflected on the related Computer Account since it is contained in the "Computer" object (therefore the Computer Account THEPUNISHER\$ will have the flag "TRUSTED\_FOR\_DELEGATION" set to "TRUE" / "1"), this means that any service started by this computer with the Service Account THEPUNISHER\$ (Computer Account) will have the Kerberos Unconstrained Delegation enabled ([so, all services started with the Local Service account such as by default the CIFS service](./not_so_brief_overview_about_kerberos/#17)).

<span id=4>{{< image src="/demystify_kerberos_delegation/4.png" position="center" style="border-radius: 8px;">}}

> By default ALL Domain Controllers have the Kerberos Unconstrained Delegation enabled.

**2. Configure the domain user that performs Kerberos authentication to the "Front-End" AP as "relayable".**

  It is necessary that the domain user that performs Kerberos authentication to the "Front-End" AP does NOT have the "NOT\_DELEGATED" flag set to "TRUE" / "1" in the "UserAccountControl" property; if it is, then that user is NOT delegable, by default ALL domain users do NOT have this flag enabled and are therefore relayable.

  {{< image src="/demystify_kerberos_delegation/5.png" position="center" style="border-radius: 8px;">}}

<br>

---
<br>

**Below we see the flow of a Kerberos authentication with "Unconstrained Delegation" enabled:**

> To simplify the creation of the lab, even though this would hardly happen in reality, in the following screenshots the Front-End AP will be the CIFS service hosted on the THEPUNISHER computer (this service, having "Local System" as Service Account, [in a Kerberos context the Service Account will be the Computer Account THEPUNISHER\$](./not_so_brief_overview_about_kerberos/#17)), in reality, usually, a Front-End AP could be a Web Application.

{{< image src="/demystify_kerberos_delegation/6.png" position="center" style="border-radius: 8px;">}}

> The "KRB_AP_REP" packet (["AP Front-End" -> "Client"](#9) & "[AP Back-End" -> "AP Front End](#10)") required by the Mutual Authentication could be sent in different times based on the Windows machine version used inside the infrastructure, this is the reason why i have not putted them on the image.

> <span id=2> Integrity and authenticity verification operations that occur within traditional Kerberos authentication (sending & analyzing the "Authenticator" along with the related "Session Key" used to encrypt & decrypt parts of the packet) are also present with Unconstrained Delegation enabled, but in this case they will NOT be mentioned, because they have already been generally described [previously](./not_so_brief_overview_about_kerberos) (for a complete analysis in the context of Unconstrained Delegation see [this guide](https://www.youtube.com/watch?v=xDFRUYv1-eU&t=326s)) and because it was preferred to instead emphasize the unique characteristics of Kerberos Unconstrained Delegation.

> [As already mentioned previously](./not_so_brief_overview_about_kerberos.md#40), below we will describe the traditional process where Kerberos with Unconstrained Delegation enabled is used, that is, from an Interactive Logon where a user enters their credentials within a WinLOGON GUI, and then subsequently uses Kerberos again in a Network Logon (roughly using cached credentials) to authenticate to a target service with Kerberos Unconstrained Delegation enabled; that said, in reality, the authentication process can also start in other types of authentications besides the traditional WinLOGON GUI (Interactive Logon).
---
<br>

**Introduction: Initially, the Client (after the domain user has entered their credentials for an Interactive Logon) makes a request for a TGT Ticket & TGS Session Key (KRB\_AS\_REQ) to the KDC and it responds (KRB\_AS\_REP) providing the requested data (if positive, in summary, the Client grants access to the domain user).**

### **1. KRB\_TGS\_REQ The Client provides its own TGT Ticket to the KDC to request the TGS Ticket.**
Now that a domain user has already authenticated to a Client (using Kerberos) and already possesses the TGT with a TGS Session Key, if they need to perform a "Network Logon" the Kerberos protocol comes into play again, specifically the Client will use the TGT and the TGS Session Key to request another type of ticket called the TGS Ticket.

The Client presents to the KDC (no longer to the AS feature) a KRB\_TGS\_REQ which in summary contains:

{{< image src="/demystify_kerberos_delegation/7.png" position="center" style="border-radius: 8px;">}}

- **Ticket TGT**: The previously received TGT ticket (to exchange it for a TGS Ticket)

- **SPN**: The SPN related to / pointing to the service the Client needs to connect to via SSO is sent in plain-text, in this case it refers to the AP Front-End, such as the SPN "HTTP/Charlotte.medin.local" or "CIFS/THEPUNISHER", in the first one the authentication will be to the HTTP service on the Hostname "Charlotte.medin.local" while in the second one to the CIFS service on the Hostname THEPUNISHER.

### **2. KRB\_TGS\_REP: The KDC sends the TGS Ticket to the Client BUT specifying that the requested service has the Kerberos Unconstrained Delegation enabled.**

The KDC receives the [KRB\_TGS\_REQ](#1-krb_tgs_req-the-client-provides-its-own-tgt-ticket-to-the-kdc-to-request-the-tgs-ticket) packet and after performing the [usual checks](#2) sees that the SPN contained within, in this example "CIFS\THEPUNISHER", points to the CIFS service hosted on the computer THEPUNISHER which has as Service Account the "Computer Account" THEPUNISHER\$ ([in Kerberos context](./not_so_brief_overview_about_kerberos.md#17)), since this "Computer Account" has the [TRUSTED\_FOR\_DELEGATION flag enabled](#4), it means the CIFS service on the computer THEPUNISHER has Kerberos Unconstrained Delegation, consequently the KDC responds to the Client with a "KRB\_TGS\_REP" containing, in summary:

{{< image src="/demystify_kerberos_delegation/8.png" position="center" style="border-radius: 8px;">}}

- **Ticket TGS**: The TGS Ticket for the AP "Front-End" (CIFS Service hosted on "THEPUNISHER") BUT with the flag "OK-AS-DELEGATE" set to TRUE

> The "FORWARDABLE" flag is also set to TRUE
<span id=6>

### **3. KRB\_TGS\_REQ: The Client requests a "Ticket TGT Forwarded" from the KDC.** 

The Client receives the packet and after performing the [usual checks](#2) sees that the TGS Ticket received has the "OK-AS-DELEGATE" flag set to TRUE, this flag indicates to the Client that the service the domain user needs to access, namely the AP Front End, has Kerberos Unconstrained Delegation enabled, consequently the Client sends again a "KRB\_TGS\_REQ" containing, in summary:

{{< image src="/demystify_kerberos_delegation/9.png" position="center" style="border-radius: 8px;">}}

- **Previously received TGT Ticket**: The previously received TGT Ticket (to exchange it this time for a "Forwarded TGT Ticket")

- **Other Data**: Since the Client knows that the AP Front End has "Kerberos Unconstrained Delegation" configured, it choose to requests a so-called "Forwarded TGT Ticket", for this purpose inside this Kerberos packet the Client specifies:

  - The SPN related to the Kerberos service (KDC) of the Domain Controller which is "krbtgt/\<domain\>" (analogous to what happens in a [KRB\_AS\_REQ](./not_so_brief_overview_about_kerberos.md#39) but this time in a KRB\_TGS\_REQ)

  - The "FORWARDED" flag set to TRUE

<span id=8>

### **4. KRB\_TGS\_REP: The KDC sends a "Ticket TGT Forwarded" to the Client**

The KDC, after performing the [usual checks](#2), since it previously sent a [KRB\_TGS\_REP](#2-krb_tgs_rep-the-kdc-sends-the-tgs-ticket-to-the-client-but-specifying-that-the-requested-service-has-the-kerberos-unconstrained-delegation-enabled) specifying that the service requested by the Client supports Kerberos Unconstrained Delegation, verifies if within the new [KRB\_TGS\_REQ](#6) received the "FORWARDED" flag is set to TRUE, if positive, the KDC responds to the Client with a "KRB\_TGS\_REP" containing, in summary:

{{< image src="/demystify_kerberos_delegation/10.png" position="center" style="border-radius: 8px;">}}

 - **The "Forwarded TGT Ticket"**: The KDC sends to the Client a so-called "Forwarded TGT Ticket", that is a TGT Ticket with the "FORWARDED" flag set to True (which contains like always the PAC of the Client's domain user).

 > I want to highlight that the KDC sent a "Forwarded TGT Ticket" within the encrypted part of a KRB\_TGS\_REP, in a traditional Kerberos authentication the KDC would issue a TGT Ticket exclusively in a [KRB\_AS\_REP](./not_so_brief_overview_about_kerberos.md#9).

<span id=7>

### **5. KRB\_AP\_REQ: The Client attempts to access the Front-End AP by providing its own TGS Ticket BUT also sharing the so-called "Ticket TGT Forwarded".**

The Client, after the [usual checks](#2), in summary, sends a "KRB\_AP\_REQ" packet to the AP Front-End (in this case to the CIFS service hosted on the computer THEPUNISHER) containing:

{{< image src="/demystify_kerberos_delegation/11.png" position="center" style="border-radius: 8px;">}}

- **Ticket TGS**: A TGS Ticket that points via SPN to the AP Front End (in this example CIFS\THEPUNISHER)

- **Forwarded TGT Ticket**: The "Forwarded TGT Ticket" that the Client received in the previous "[KRB\_TGS\_REP"](#8).

> I want to highlight that the "Forwarded TGT Ticket" sent is contained within the "authenticator" field of the "TGS Ticket".
---

**So, what happens now?**

The AP Front End, now having received the [KRB\_AP\_REQ](#7) packet, in summary, after the [usual checks](#2), performs the following actions:

1.  The AP Front End will allow ([if the AUTHORIZATION phase goes correctly](./not_so_brief_overview_about_kerberos#3)) the Client access to the requested service (in this case the CIFS service hosted on the computer THEPUNISHER), subsequently, depending on the requested service and if mutual authentication is required by the Client, the AP Front End will send a KRB\_AP\_REP to the Client.

> <span id=9> In my home lab the KRB\_AP\_REP packet was sent in this scenario, [in this other case](https://www.youtube.com/watch?v=xDFRUYv1-eU&t=326s), however, the KRB\_AP\_REP packet was delivered to the Client only at the end of the entire process.

2.  The AP Front End will now extract the "Forwarded TGT Ticket" contained within the TGS Ticket and cache it locally to potentially impersonate the Client in future interactions.

----

**If the AP Front End needs to authenticate to an AP Back End on behalf of the Client, the following actions will occur:**

### **6. KRB\_TGS\_REQ: The Front-End AP provides the Client’s "Ticket TGT Forwarded" to the KDC to request a TGS Ticket.**

Occasionally, when the AP Front End will need to authenticate to the AP Back End on behalf of the Client, the AP Front End will send to the KDC a "KRB\_TGS\_REQ" packet built [as already indicated previously](#1-krb_tgs_req-the-client-provides-its-own-tgt-ticket-to-the-kdc-to-request-the-tgs-ticket), with the only difference that the Client’s "Ticket TGT Forwarded" will be shared instead (it contains the domain user’s PAC), in this way the AP Front End will be able to obtain a valid TGS Ticket to authenticate to the AP in the Back-End on behalf of the Client.

### **7. KRB\_TGS\_REP: The KDC sends the TGS Ticket to the Front-End AP.**

The KDC, in summary, after the [usual checks](#2), will provide the AP Front End with a TGS Ticket specific for the AP in the Back End.

> [As already said](./not_so_brief_overview_about_kerberos#42), the PAC of the TGS Ticket is a copy of the PAC contained in the provided TGT Ticket, consequently the TGS Ticket that the KDC will provide to the AP Front End will still belong to the Client.

### **8. KRB\_AP\_REQ: The AP Front End presents the TGS Ticket to the AP Back End to authenticate on behalf of the Client.**

The AP Front End will send a "KRB\_AP\_REQ" packet to the AP Back End, authenticating by essentially sharing the previously received TGS Ticket, since this TGS Ticket belongs to the Client (it contains the domain user’s PAC), the AP Front End will authenticate to the AP Back End on behalf of the Client.

Finally, if the AP Front End requests mutual authentication, the AP Back End will reply to the AP Front End with a "KRB\_AP\_REP".

> <span id=10> This is what happens in my home lab, [in this other case](https://www.youtube.com/watch?t=326&v=xDFRUYv1-eU&feature=youtu.be) instead, the "KRB\_AP\_REP" packet is first sent from the AP Back End to the AP Front End and then [as already told](#9) another "KRB\_AP\_REP" from the AP Front End to the Client.

## **Constrained Delegation**

As we have seen, the "Unconstrained Kerberos Delegation" can be extremely dangerous since the AP Front End caches the Client’s TGT Ticket and can also impersonate the user towards ANY AP in the Back End, for this reason Microsoft developed a more restrictive (a.k.a "Constrained") version of Kerberos Delegation called "Constrained Delegation", specifically it supports 2 Kerberos extensions known as [Service For User (S4U)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94):

1. Service for User to Proxy (S4U2Proxy): Allows the AP Front End to obtain a TGS Ticket on behalf of the Client in order to use it in an authentication to the AP in the Back End.

2. Service for User to Self (S4U2Self): Allows the AP Front End to obtain a TGS Ticket valid for itself on behalf of any Client, such Ticket can be used by the AP Front End as evidence that the Client has authenticated to it.

By using these Kerberos extensions it is possible to restrict (Constrained) the functionality of Kerberos Delegation by ensuring that the AP Front End can authenticate on behalf of the Client exclusively to a predefined set of APs in the Back End, furthermore, to achieve this, the Client’s TGT Ticket is NOT required and therefore there is no risk of it being cached.

Below there is a diagram showing how the Constrained Delegation works:

{{< image src="/demystify_kerberos_delegation/12.png" position="center" style="border-radius: 8px;">}}

It is possible to configure Constrained Delegation on the AP Front End in 2 different modes:

- **Trust this computer for delegation to specified service only (Kerberos only)**: The AP Front End is able to impersonate the Client only if the Client logs into it via Kerberos (it uses the S4U2Proxy extension);this scenario is also called **"Kerberos Only"**.

- **Trust this computer for delegation to specified service only (Use any authentication protocol)**: The AP Front End is able to impersonate the Client if the Client logs into it with any type of protocol, such as NTLM (it uses the S4U2Self & S4U2Proxy extensions); this scenario is also called **"Protocol Transition"**.

To analyze with Wireshark ALL the flows that occur during this Constrained Delegation I would have had to create from scratch a lab composed of a Front End Service that accepts a Kerberos authentication and develop within it a logic that triggers an additional Kerberos authentication towards the Back-End Server, since I did not find a quick method on how to do this, the screenshots you will see in this section come from this [awesome guide](https://www.youtube.com/watch?v=gzqq2r6cZjc&t=2779s).

## **Constrained Delegation (Kerberos only)**

The KDC, in order to use the "Constrained Delegation (Kerberos only)", requires 2 prerequisites:

**1. Configure the "Constrained Delegation (Kerberos only)" on the "Front-End" AP.**

<span id=15>

{{< image src="/demystify_kerberos_delegation/13.png" position="center" style="border-radius: 8px;">}}

  The "Constrained Delegation (Kerberos only)" is configured via [ADUC](https://serveracademy.com/blog/active-directory-users-and-computers-aduc-installation-and-tutorial/) by enabling the property "Trust this computer for delegation to specified service only (Kerberos only)" on the "Computer" object that acts as the "Front-End" AP; since this configuration is potentially dangerous, such action can only be performed by a Domain Admin account or an account with the "[SeEnableDelegationPrivilege](https://harmj4.rssing.com/chan-30881824/article60.html)" permission.

  > In reality, even an object of type "user" (domain account) can be configured with the Kerberos Constrained Delegation (Kerberos only), in this way such domain account will be able to impersonate another domain account to authenticate against target APs (services), however, to do this it is necessary that such account has at least 1 SPN configured, in fact only in this specific case the "Delegation" tab will appear inside the property of the user object; specifically, the "Kerberos Only" flow described later will remain unchanged with the only difference that when referring to the Service Account "Computer Account," the Service Account "User" will be used instead.

Furthermore, it is mandatory to fill the section indicated just below; with it, the domain administrator is able to restrict (a.k.a constrain) which Back-End APs the Front-End AP can authenticate on behalf of the Client.

This configuration sets in the [UserAccountControl](#11) property of the AP "Front End" object the flag "msds-allowedtodelegateto", which contains in the form of SPNs all the "Back End" APs for which the "Front End" AP has permission to authenticate on behalf of the Client.

In our [example](#15), the Kerberos Delegation is configured on the Computer "WEB01" which will act as the Front-End AP, this modification is actually reflected on the related Computer Account since it is contained in the "Computer" object, so the Computer Account "WEB01\$" will have the "msds-allowedtodelegateto" property filled, this means that any service started by this computer with the Service Account WEB01\$ (Computer Account) will have "Kerberos Constrained Delegation (Kerberos Only)" enabled ([so, all services started with the Local Service account such as by default the CIFS service or HTTP like in this example](./not_so_brief_overview_about_kerberos/#17)).

<span id=25>
{{< image src="/demystify_kerberos_delegation/14.png" position="center" style="border-radius: 8px;">}}

In conclusion, all services started with the WEB01\$ user, such as in this case the HTTP service (AP Front End), will have "Constrained Delegation (Kerberos only)" enabled; so, in this scenario, they will be able to authenticate on behalf of the Client exclusively on the CIFS service of the SQL01 computer (AP Back-End).

**2. Configure the domain user that performs Kerberos authentication to the "Front-End" AP as "relayable".**

  It is necessary that the domain user that performs Kerberos authentication to the "Front-End" AP does NOT have the "NOT\_DELEGATED" flag set to "TRUE" / "1" in the "UserAccountControl" property; if it is, then that user is NOT delegable, by default ALL domain users do NOT have this flag enabled and are therefore relayable.

  {{< image src="/demystify_kerberos_delegation/5.png" position="center" style="border-radius: 8px;">}}

<br>

---
<br>

**Below we see the flow of a Kerberos authentication with "Constrained Delegation (Kerberos only)" enabled:**

{{< image src="/demystify_kerberos_delegation/15.png" position="center" style="border-radius: 8px;">}}

> The "KRB_AP_REP" packet ("[AP Front-End" -> "Client"](#12)) & "AP Back-End" -> "AP Front End") required by the Mutual Authentication could be sent in different times based on the Windows computer version used inside the infrastructure, with this flow i choose to put down the most common scenario.

> <span id=2> Integrity and authenticity verification operations that occur within traditional Kerberos authentication (sending & analyzing the "Authenticator" along with the related "Session Key" used to encrypt & decrypt parts of the packet) are also present with Unconstrained Delegation enabled, but in this case they will NOT be mentioned, because they have already been generally described [previously](./not_so_brief_overview_about_kerberos) (for a complete analysis in the context of Unconstrained Delegation see [this guide](https://www.youtube.com/watch?v=xDFRUYv1-eU&t=326s)) and because it was preferred to instead emphasize the unique characteristics of Kerberos Unconstrained Delegation.

> [As already mentioned previously](./not_so_brief_overview_about_kerberos.md#40), below we will describe the traditional process where Kerberos with Unconstrained Delegation enabled is used, that is, from an Interactive Logon where a user enters their credentials within a WinLOGON GUI, and then subsequently uses Kerberos again in a Network Logon (roughly using cached credentials) to authenticate to a target service with Kerberos Unconstrained Delegation enabled; that said, in reality, the authentication process can also start in other types of authentications besides the traditional WinLOGON GUI (Interactive Logon).


---
<br>

**Introduction: Initially, the Client (after the domain user has entered their credentials for an Interactive Logon) makes a request for a TGT Ticket & TGS Session Key (KRB\_AS\_REQ) to the KDC and it responds (KRB\_AS\_REP) providing the requested data (if positive, in summary, the Client grants access to the domain user).**

### **1. KRB\_TGS\_REQ: The Client provides its TGT Ticket to the KDC to request the TGS Ticket.**

Now that a domain user has already authenticated to a Client (using Kerberos) and already holds the TGT Ticket with a TGS Session Key, if there is a need to perform a "Network Logon" login, the Kerberos protocol comes into play again, specifically the Client will use the TGT Ticket and the TGS Session Key to request another type of ticket called the TGS Ticket.

The Client presents to the KDC (no longer to the AS functionality) a KRB\_TGS\_REQ which in summary contains:

- The Client shares its previously received TGT Ticket (to exchange it for a TGS Ticket)

- SPN: The SPN related to / pointing to the service that the Client needs to connect to via SSO is sent in plain text, in this case it refers to the AP Front-End, such as the SPN "HTTP/WEB01", that is, a request for authentication to the HTTP service present on the hostname "WEB01" is made.
<span id=23>
### **2. KRB\_TGS\_REP: The KDC sends the TGS Ticket to the Client.**

The KDC receives the KRB\_TGS\_REQ packet and, after performing the [usual checks](#2), sends a "KRB\_TGS\_REP" packet containing in summary:

- The TGS Ticket for the "Front End" AP (HTTP Service hosted on "WEB01")

### **3. KRB\_AP\_REQ: The Client attempts to access the Front-End AP by providing its TGS Ticket**

After the [usual checks](#2), the Client, in summary, sends a "KRB\_AP\_REQ" packet to the Front-End AP (HTTP service) containing in summary:

- Ticket TGS: Its own TGS Ticket ([previously received](#2-krb_tgs_rep-the-kdc-sends-the-tgs-ticket-to-the-client))

### **4. KRB\_AP\_REP (Optional): The AP Front End (HTTP) will allow the Client access to the requested service:**

The AP Front End, now that it has received the KRB\_AP\_REQ packet, in summary, after the [usual checks](#2), will allow ([if the AUTHORIZATION phase goes correctly](./not_so_brief_overview_about_kerberos#3)) the Client access to the requested service (in this case the HTTP service hosted on the WEB01 computer), subsequently, depending on the requested service and if mutual authentication is required by the Client, the AP Front End will send a "KRB\_AP\_REP" to the Client.

> <span id=12> In my home lab the KRB\_AP\_REP packet was sent in this way, [in this other case](https://youtu.be/gzqq2r6cZjc?t=1309), however, the KRB\_AP\_REP packet was delivered to the Client only at the end of the entire process.

---

**If the AP Front End needs to authenticate to a Back End AP on behalf of the Client, the following actions will take place:**

---

### **5. KRB\_TGS\_REQ (S4U2Proxy) / S4USelf Request**

Occasionally, when the AP Front End (so the HTTP service) needs to authenticate to the Back End AP (so the CIFS service) on behalf of the Client, the AP Front End will send to the KDC a "KRB\_TGS\_REQ (S4U2Proxy)" packet containing, in summary:

- **The AP Front End shares its own TGT Ticket**:

  Every computer joined in a domain, during its startup, will perform a Kerberos authentication using its corresponding Computer Account; consequently the WEB01 computer will also have stored in memory the TGT Ticket of the WEB01\$ account.

  In this scenario, the AP Front End will send the TGT Ticket of its Computer Account.

  {{< image src="/demystify_kerberos_delegation/16.png" position="center" style="border-radius: 8px;">}}

<span id=24>

- **SPN of the Back-End service:**

  The SPN related to / pointing to the Back-End service that the Front-End service needs to connect to on behalf of the Client is sent, in this case, it refers to the Back-End AP identified by the SPN "CIFS/SQL01", so the CIFS service hosted on the "SQL01" computer.

  {{< image src="/demystify_kerberos_delegation/17.png" position="center" style="border-radius: 8px;">}}

<span id=20>

- **Client's TGS Ticket:**

  The TGS Ticket that the Client used to access the AP Front End (HTTP service on the WEB01 computer) will be sent.

  This TGS Ticket is contained within the "Additional Ticket" field:

  {{< image src="/demystify_kerberos_delegation/18.png" position="center" style="border-radius: 8px;">}}

  <span id=21> Additionally, it should be noted that the sent TGS Ticket will have the "Forwardable" flag set to "1"; by default, all TGS Tickets have this characteristic, that said, in this scenario this flag will be interpreted and therefore it is important to specify it.

  {{< image src="/demystify_kerberos_delegation/19.png" position="center" style="border-radius: 8px;">}}

<span id=22>

- **The flags "Resource-Based Constrained-Delegation" & "Constrained-Delegation" both set to "1" / "TRUE":**

  The AP Front End, within the KRB\_TGS\_REQ packet, will set the flags "Resource-Based Constrained-Delegation" & "Constrained-Delegation" both to "1" / "TRUE"; this is done because in case of a FallBack, so if the "Constrained Delegation (Kerberos only)" fails, the Delegation can proceed with "Resource-Based Constrained Delegation (RBCD) flow".

  {{< image src="/demystify_kerberos_delegation/20.png" position="center" style="border-radius: 8px;">}}
  <br>
  {{< image src="/demystify_kerberos_delegation/21.png" position="center" style="border-radius: 8px;">}}

### **6. KRB_TGS_REP (S4U2Proxy) / S4USelf Response**

The KDC, after performing authenticity checks and analyzing the KRB_TGS_REQ (S4U2Proxy) packet received from the AP Front, will perform further verifications **sequentially**:

1. The KDC verifies if the ["TGS Ticket" used by the Client to access the AP Front End (HTTP/WEB01)](#20) is inside in the received [KRB_TGS_REQ (S4U2Proxy)](#5-krb_tgs_req-s4u2proxy--s4uself-request) packet, which would provide to the KDC the evidence that the Client has indeed authenticated to the AP Front End (HTTP Service on the WEB01 machine) (and therefore that the AP Front End can potentially impersonate the Client); it also checks that this TGS Ticket has the "FORWARDABLE" flag set to "1") ([positive result in this case](#21))

> As detailed by [Microsoft's wiki](https://www.youtube.com/watch?t=2487&v=gzqq2r6cZjc&feature=youtu.be), if the TGS Ticket does NOT have the ["FORWARDABLE" flag](#21) set & [if the RBDC flag was NOT configured in the KRB_TGS_REQ (S4U2Proxy)](#22), then the KDC would respond with an error (KRB_ERRBADOPTION); instead, if the RBDC flag is set (by default it is), the KDC will attempt to use RBCD Delegation.
>
> In the typical scenario, like the used in our example, the TGS Ticket sent in the KRB_TGS_REQ (S4U2Proxy) will always have the FORWARDABLE flag TRUE, because it was received by a traditionally ["KRB_TGS_REP"](#23), consequently Kerberos Constrained Delegation (Kerberos Only) practically NEVER  fails and so the fallback case where "Resource Based Constrained Delegation (RBCD") would be used is extremely rare.

2. The KDC, inspecting the [SPN contained in the KRB_TGS_REQ (S4U2Proxy) packet](#24), will understand that the AP Front End (ex HTTP/WEB01) intends to authenticate to a specific AP Back-End (ex CIFS/SQL01) on behalf of the Client; consequently, the KDC retrieves the Service Account of the AP Front End (WEB01$) and checks if the SPN of the requested AP Back End (in this case CIFS/SQL01) is present in its "msds-allowedtodelegateto" property ([positive result in this case](#25))

If both verifications are positive, as in our case, then the KDC sends a KRB_TGS_REP (S4U2Proxy) packet to the AP Front End containing, in summary:

- **A TGS Ticket of the Client to access the AP Back-End**:

  The KDC then sends within a "KRB\_TGS\_REP (S4U2Proxy)" a TGS Ticket belonging to the Client (containing the PAC of the domain user who authenticated to the AP Front End - inside the image, in the field dedicated to the user name i just wrote a placeholder to avoid a screenshot madness) valid for the AP Back-End (CIFS/SQL01)
  
  {{< image src="/demystify_kerberos_delegation/22.png" position="center" style="border-radius: 8px;">}}
  
  Furthermore, i want to highlight that the TGS Ticket sent will have the "Forwardable" flag set to "1", by default this characteristic is present in ALL TGS Tickets; that said, in this scenario the flag will be interpreted and therefore it is important to clarify.

  {{< image src="/demystify_kerberos_delegation/23.png" position="center" style="border-radius: 8px;">}}

### **7. KRB\_AP\_REQ:**

The AP Front End (HTTP service), after the [usual checks](#2), in summary, sends a "KRB\_AP\_REQ" packet to the AP Back-End (CIFS service) containing, in summary:

- **The previously received TGS Ticket**: The previously received TGS Ticket, that is, the one belonging to the Client (containing the PAC of the domain user who authenticated to the AP Front End) and valid for the AP Back-End (CIFS/SQL01).

### **8. KRB\_AP\_REP (Optional)**

The AP Back-End, now having received the KRB\_AP\_REQ packet from the AP Front-End, in summary, after the [usual checks](#2) ([if the AUTHORIZATION phase goes correctly](./not_so_brief_overview_about_kerberos#3), will allow access by the AP Front End to the requested service (in this case the CIFS service hosted on the SQL01 machine); subsequently, depending on the requested service and if mutual authentication is required by the AP Front End (ex HTTP service), the AP Back-End (ex CIFS service) will send a KRB\_AP\_REP to the AP Front End (ex HTTP service).

> This is what happens in my home lab; [in this case](https://www.youtube.com/watch?t=1309&v=gzqq2r6cZjc&feature=youtu.be), however, the "KRB\_AP\_REP" packet is sent first by the AP Back-End to the AP Front-End and then  ([as already told](#12)) another "KRB\_AP\_REP" is sent from the AP Front End to the Client.

In this way, the AP Front-End has successfully authenticated to the AP Back-End on behalf of the Client.

## **Constrained Delegation (Use any authentication Protocol) / Protocol Transition**

In a "[Constrained Delegation (Kerberos Only)](#constrained-delegation-kerberos-only)" the AP Front End (ex HTTP) can use the S4U2Proxy extension to obtain from the KDC the Client’s TGS Ticket (ex MARVEL\pparker) to access the AP Back End (ex CIFS); to do this, the AP Front End (ex HTTP) must share the TGS Ticket that the Client (ex MARVEL\pparker) used to authenticate to it, that said, if the AP Front End (ex HTTP) does NOT have such TGS Ticket because the Client authenticated using, for example, NTLM or Basic authentication, this method cannot be used, and for this reason the "S4USelf" extension was created.

In this scenario the AP Front End (ex HTTP) can invoke the S4U2Self extension, in other words, it requests from the KDC a TGS Ticket of a specific Client (ex MARVEL\pparker) valid exclusively for itself (ex HTTP), this can then be used by the AP Front End as "evidence" to subsequently invoke the S4U2Proxy extension; this scenario is called "Constrained Delegation (Use any authentication protocol)".

The KDC, in order to use the "Constrained Delegation (Kerberos only)", requires 2 prerequisites:

**1. Configure the "Constrained Delegation (Use any authentication protocol)" on the "Front-End" AP.**

<span id=25>

{{< image src="/demystify_kerberos_delegation/24.png" position="center" style="border-radius: 8px;">}}

  The "Constrained Delegation (Use any authentication protocol)" is configured via [ADUC](https://serveracademy.com/blog/active-directory-users-and-computers-aduc-installation-and-tutorial/) by enabling the property "Trust this computer for delegation to specified service only (Use any authentication protocol)" on the "Computer" object that acts as the "Front-End" AP; since this configuration is potentially dangerous, such action can only be performed by a Domain Admin account or an account with the "[SeEnableDelegationPrivilege](https://harmj4.rssing.com/chan-30881824/article60.html)" permission.

  > In reality, even an object of type "user" (domain account) can be configured with the "Constrained Delegation (Use any authentication protocol)", in this way such domain account will be able to impersonate another domain account to authenticate against target APs (services), however, to do this it is necessary that such account has at least 1 SPN configured, in fact only in this specific case the "Delegation" tab will appear inside the property of the user object; specifically, the "Kerberos Only" flow described later will remain unchanged with the only difference that when referring to the Service Account "Computer Account," the Service Account "User" will be used instead.

Furthermore, it is mandatory to fill the section indicated just below; with it, the domain administrator is able to restrict (a.k.a constrain) which Back-End APs the Front-End AP can authenticate on behalf of the Client.

This configuration sets in the [UserAccountControl](#11) property of the AP "Front End" object:

- The "TRUSTED\_TO\_AUTH\_FOR\_DELEGATION" flag (it is different from [TRUSTED\_FOR\_DELEGATION of Unconstrained Delegation](#25))

- The "msds-allowedtodelegateto" flag, which contains in the form of SPNs all the AP "Back End" services to which the AP "Front End" is allowed to authenticate on behalf of the Client;

In our [example](#25), the Kerberos Delegation is configured on the Computer "WEB01" which will act as the Front-End AP, this modification is actually reflected on the related Computer Account since it is contained in the "Computer" object, so the Computer Account "WEB01\$" will have the "msds-allowedtodelegateto" & "TRUSTED_TO_AUTH_FOR_DELEGATION" property filled, this means that any service started by this computer with the Service Account WEB01\$ (Computer Account) will have "Constrained Delegation (Use any authentication protocol)" enabled ([so, all services started with the Local Service account such as by default the CIFS service or HTTP like in this example](./not_so_brief_overview_about_kerberos/#17)).

<span id=30>

  {{< image src="/demystify_kerberos_delegation/25.png" position="center" style="border-radius: 8px;">}}

In conclusion, all services started with the WEB01\$ user, such as in this case the HTTP service (AP Front End), will have "Constrained Delegation (Use any authentication protocol)" enabled; so, in this scenario, they will be able to authenticate on behalf of the Client exclusively on the CIFS service of the SQL01 computer (AP Back-End).

**2. Configure the domain user that performs Kerberos authentication to the "Front-End" AP as "relayable".**

  It is necessary that the domain user that performs Kerberos authentication to the "Front-End" AP does NOT have the "NOT\_DELEGATED" flag set to "TRUE" / "1" in the "UserAccountControl" property; if it is, then that user is NOT delegable, by default ALL domain users do NOT have this flag enabled and are therefore relayable.

  {{< image src="/demystify_kerberos_delegation/5.png" position="center" style="border-radius: 8px;">}}

<br>

---
<br>

**Below we see the flow of a Kerberos authentication with Constrained Delegation (Use any authentication protocol) enabled:**

{{< image src="/demystify_kerberos_delegation/26.png" position="center" style="border-radius: 8px;">}}

> The "KRB_AP_REP" packet (["AP Front-End" -> "Client"](#9) & "[AP Back-End" -> "AP Front End](#10)") required by the Mutual Authentication could be sent in different times based on the Windows machine version used inside the infrastructure, this is the reason why i have not putted them on the image.

> <span id=2> Integrity and authenticity verification operations that occur within traditional Kerberos authentication (sending & analyzing the "Authenticator" along with the related "Session Key" used to encrypt & decrypt parts of the packet) are also present with Unconstrained Delegation enabled, but in this case they will NOT be mentioned, because they have already been generally described [previously](./not_so_brief_overview_about_kerberos) (for a complete analysis in the context of Unconstrained Delegation see [this guide](https://www.youtube.com/watch?v=xDFRUYv1-eU&t=326s)) and because it was preferred to instead emphasize the unique characteristics of Kerberos Unconstrained Delegation.

> [As already mentioned previously](./not_so_brief_overview_about_kerberos.md#40), below we will describe the traditional process where Kerberos with Unconstrained Delegation enabled is used, that is, from an Interactive Logon where a user enters their credentials within a WinLOGON GUI, and then subsequently uses Kerberos again in a Network Logon (roughly using cached credentials) to authenticate to a target service with Kerberos Unconstrained Delegation enabled; that said, in reality, the authentication process can also start in other types of authentications besides the traditional WinLOGON GUI (Interactive Logon).
---
<br>

### **1. Client authenticates to an AP Front End NOT using Kerberos.**

A domain user authenticates to an AP Front End NOT using the Kerberos protocol (NTLM, Basic, etc).

**If the AP Front End needs to authenticate to an AP Back End on behalf of the Client, the following actions will take place:**

### **2. KRB\_TGS\_REQ (S4U2Self) / S4USelf Request.**

Occasionally, when the AP Front End (ex HTTP service) needs to authenticate to the AP Back End (ex CIFS service) on behalf of the Client (ex CAPSULE.corp\vegeta), since the Client (ex CAPSULE.corp\vegeta) authenticated using, for example, the NTLM protocol, the AP Front End will NOT have the Client’s TGS Ticket and therefore will NOT be able to invoke S4U2Proxy as in the [Constrained Delegation (Kerberos Only)](#constrained-delegation-kerberos-only) scenario, consequently the AP Front End will resort to the "S4U2Self" extension, that is, it will send to the KDC a "KRB\_TGS\_REQ" packet containing, in summary:

Note: The S4U2Self extension in summary serves to obtain a TGS Ticket belonging to a specific Client (ex CAPSULE.corp\vegeta) valid for the service itself, namely for the AP Front End (ex HTTP).






## Beahviour Change about Kerberos Delegation on Modern Windows System


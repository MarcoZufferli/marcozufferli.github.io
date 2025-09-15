
---
title: "Not So Brief Overview about Kerberos"
date: 2025-09-11T17:20:24+02:00
draft: false
toc: true
---

{{< image src="/not_so_brief_overview_about_kerberos/immagine.jpg" position="center" style="border-radius: 8px;">}}

# **Kerberos Authentication Protocol**

Kerberos is the Windows network authentication protocol present by default in versions after Windows 2000; it replaces the NTLM protocol (specifically, NTLMv2) but it should be noted that it can only operate in Active Directory contexts and NOT in Workgroup.

In a traditional Active Directory authentication scenario, when a user performs a domain authentication on a WorkStation / Server (Interactive Logon) the Client uses the Kerberos protocol for authentication and if, subsequently, the domain user already logged into the Client needs to authenticate with their domain credentials towards a target network service such as SMB (Network Logon), the Kerberos protocol, having SSO capabilities, is used again by the Client.

In a Microsoft Active Directory domain, Kerberos is the primary authentication mechanism, for both Interactive Logon and Network Logon (actually also for other LogonTypes), that said, if for any reason the Kerberos protocol CANNOT operate (as when performing a network authentication specifying an IP as the [target and not a hostname in Windows utilities](https://zer1t0.gitlab.io/posts/attacking_ad/#ntlm-in-active-directory), and in fact this is a method to force NTLMv2 authentication over Kerberos) Windows will use the previously available network authentication protocol, that is (usually) NTLMv2; that said, in this section we will detail the Kerberos protocol in all its phases, starting from a scenario that unfolds with an Interactive Logon up to a possible Network Logon.

Kerberos works over the TCP and UDP protocol in clear-text, in fact there is no possibility to implement encryption of the entire communication channel using OpenSSL, this is because it is the Kerberos protocol itself that is responsible for encryption, consequently the encryption mechanism of the Kerberos protocol consists of sending a series of partially already encrypted packets within an unencrypted connection (communication channel).

Kerberos is an authentication protocol, not an authorization protocol, this means that the Kerberos protocol, through the use of TGT, TGS tickets and other related data, is able both to prove to the remote service that the domain user trying to access is indeed a valid domain user, already authenticated and present in the AD (Network Logon) ([link](#1)), and to the Client when the user performs a standard login to the machine (Interactive Logon) ([link](#2)); instead, authorization, so the verification of the permissions in order to access to the target service is the responsibility of the AP, that is the server hosting the service (Network Logon) ([link](#3)), while to the Client it's the responsibility of the Client itself (Interactive Logon) ([link](#4)).

Kerberos implements the concept of "Ticket", that's are "objects" that will be used to perform domain authentications.
This protocol is called Kerberos, like the three-headed dog of Greek mythology, because in its complete operation (for example from Interactive Logon to Network Logon) it involves 3 distinct actors:

- **Client / User**: The Client (it's also possible to say the user who has logged into the Client) wants to access a service that requires domain authentication.

- **Application Server (AP)**: The service that the client (or user) wants to access.

- **Key Distribution Center (KDC)**: The Kerberos protocol, to operate, requires the involvement of a Third Party called the Key Distribution Center, which is a functionality of the DC and will be the true core of the protocol and the responsible entity (through its features) for issuing the different Tickets.

    <span id="7">Specifically, the KDC supports a functionality called Authentication Server (AS), this feature is the one that will actually issue the Tickets called TGT, in some guides it is also said that the KDC has another functionality called Ticket-Granting Server which will be responsible for issuing the other type of Ticket, that is the TGS, that said, for simplicity in this section, instead of specifying the Ticket-Granting Server we will say that it is the KDC itself that issues the TGS.

The Active Directory of a Domain Controller will act as the KDC and the listening ports that expose the service (and therefore the functionalities) of Kerberos will be 88 TCP and 88 UDP.

**Kerberos Flow:**

{{< image src="/not_so_brief_overview_about_kerberos/kerberos_flow.png" position="center" style="border-radius: 8px;" >}}

> In the following sections we'll describe the traditional process where Kerberos is used, so from an Interactive Logon where a user enters their credentials within a WinLOGON GUI, to a subsequent Network Logon (using the credentials cached) to authenticate to a target service; in reality, the Kerberos authentication process can actually also begin using other [Logon Type](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them) besides the traditional WinLOGON GUI (Interactive Logon), for example: performing a Kerberos authentication to a service (for instance the SMB service using the PsExec utility from Sysinternals) specifying domain credentials that are different from the ones currently in use; since the Client does NOT have the TGT Ticket of the requested credentials cached (because it logged into the Client with another account) a full Kerberos authentication will be performed.

## **Kerberos Flow - Interactive Login**

1. ### **KRB_AS_REQ: Request of the TGT Token from the Authentication Server (AS)**

    The Kerberos protocol is (typically) initialized when a user needs to perform an [Interactive Logon](https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/windows-logon-scenarios#BKMK_InteractiveLogon) ([1](https://zer1t0.gitlab.io/posts/attacking_ad/#interactive-logon)) within a Client using domain credentials, that is by filling in the traditional Windows credential form, also called WinLogon GUI.

    {{< image src="/not_so_brief_overview_about_kerberos/interactive_logon.png" position="center" style="border-radius: 8px;" >}}

    To authenticate, the user enters the credentials on the Client (DOMAIN\User & Password) and everywhing will be shared in cleartext with the "LSASS" process.

    <span id="6">After that, LSASS delegates the authentication to its SSPs, so some DLLs (APIs) that can be loaded within the "lsass.exe" process, consequently the LSASS process loads and shares in cleartext the credentials with all the SSPs dedicated to authentication (kerberos.dll - manage Kerberos, msv1_0.dll - manage NTLM Authentication, wdigest.dll - manage Digest); that said, since the LSASS process does NOT know which SSP to use, [it will use them one by one in sequential order until a correct authentication takes place](https://syfuhs.net/what-happens-when-you-type-your-password-into-windows), consequently, since Windows will recognize that it is a domain user entered, it will start with the "kerberos.dll" DLL, it then calculates the NT hash of the corresponding previously entered password (which it received in plaintext) and after that contacts the AS (Authentication Service which is a feature of the KDC, that is the DC) to request the issuance of a Ticket called "TGT" and a "TGS Session Key", specifically the LSASS process sends a KRB_AS_REQ which contains:

    {{< image src="/not_so_brief_overview_about_kerberos/krb_as_req.png" position="center" style="border-radius: 8px;" >}}

      - **Authenticator**: the timestamp contained within it will be encrypted with the user’s hash, while other values such as the ‘username’ field, which contains the name of the domain user we are logging in with, will all be in plain-text.
        
      - <span id="5">**SPN - krbtgt**: It will be indicated in the dedicated field, the SPN related to the Kerberos service (KDC) of the Domain Controller which is equal to krbtgt/[\<domain\>].

        A Service Principal Name (SPN), [as we explain later](#service-principal-name-spn) is a unique identifier for the instance of a service, SPNs are used by Kerberos authentication to associate the instance of a service (simplifying: the start & running of the service such as for example Microsoft SQL) with a so-called "Logon Account", so a domain user (which in this way it will becomes a Service Account); in other terms, (generically speaking) an SPN can be considered as a generic object that represents the association between a service and a domain user, that said, technically, [it is an attribute of the "Users" object](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772815(v=ws.10)#service-principal-names) and in fact from it one can list the related SPNs; this essentially means that through an SPN it is possible to map the start & the running of a service present on a server with a domain user rather than associating it with a "Standard Service Account" such as [NetworkService Account](https://learn.microsoft.com/it-it/windows/win32/services/networkservice-account?redirectedfrom=MSDN); finally, it should be noted that also Computer Accounts have SPNs.
    > **Note 1**: If the DC is not accessible when a Client performs a domain authentication, the Client checks whether such credentials are present within the [Domain Credential Cached (DCC)](https://learn.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/cached-domain-logon-information) which stores the last domain users logged into the machine (only if a user authenticates correctly and has the permissions to access the Client), if they are also NOT present there then the login is rejected.
    
    > **Note 2**: As we will see later, if a domain user has the [DONT_REQ_PREAUTH](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties) flag enabled, the AS will respond with a valid KRB_AS_REP (response) even if the KRB_AS_REQ (request) packet does not have the "Timestamp" encrypted with the NTHash of the user’s password.
    
    > <span id=32> **Note 3**: For simplicity of explanation everything has been described in this way, in reality, what will happen in reality is that the Client will first send a "KRB_AS_REQ" packet to the AS NOT encrypting the Timestamp with the NT Hash of the current user and only when the AS responds with an error "KDC_ERR_PREAUTH_REQUIRED" then the Client will send a new "KRB_AS_REQ" with the Timestamp encrypted, this is the reason why by analyzing everything with Wireshark in a traditional Kerberos authentication one can notice such error message.

2. ### **KRB_AS_REP: AS sends the TGT token to the Client**

<span id="9">
The AS (a feature of the KDC) after having received such request, using the username (which is not encrypted) as a keyword searches inside its Database for the password of that user in order to decrypt the message; if the AS correctly decrypts the message and the now decrypted timestamp falls within the time difference configured in the KDC, then the authentication has occurred successfully.

> If the domain user contained in the first KRB_AS_REQ interaction has the [DONT_REQ_PREAUTH](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties) property flag enabled, the AS will accept such authentication request as valid EVEN if the request does NOT have the "timestamp" value encrypted with the NT Hash of the domain user, in such case the AS will simply verify directly whether the timestamp falls within the time difference configured in the KDC; it is important to underline that if the domain user has such flag enabled, the AS will nevertheless respond with a valid KRB_AS_REP both if the KRB_AS_REQ packet has the "timestamp" encrypted (usually sent by the LSASS process in an Interactive Logon) and if it does NOT have the timestamp encrypted (usually sent by an attacker if performing an AS-REP Roasting Attack).

If everything goes well, the AS responds to the client with a packet called KRB_AS_REP containing the TGT Ticket and the TGS Session Key (called "Session Key" within the screenshot), such TGS Session Key will be used subsequently as an encryption key for the possible following requests.

The KRB_AS_REP packet sent by the AS to the Client contains:

<span id="12">{{< image src="/not_so_brief_overview_about_kerberos/krb_as_rep.png" position="center" style="border-radius: 8px;">}}
- **Ticket TGT**: The TGT Ticket which has been encrypted with the "krbtgt hash", that is the hash (NT Hash) of the domain user called "krbtgt" ([as previously specified](#5))
    <span id="8">Since the Client for obvious reasons does not know the password hash of the KDC it cannot decrypt the TGT Ticket, this is not a problem because to obtain the TGS Ticket in the next step it is sufficient to send the TGT ticket as we received it, that is, encrypted.

- **Other Data**: Other various data, including the TGS Session Key, are encrypted with the hash (NT Hash) of the Client user who requested the domain authentication via Interactive Logon, in this way the KRB_AS_REP packet when sent by the AS to the Client, even if intercepted via Man-In-The-Middle, the attacker could not (hopefully 😉) decrypt the packet since they do not know the hash of the Client user.
> The AS will respond to the Client by sending a KRB_AS_REP with the TGS Session Key (plus other data) encrypted with the NTHash of the domain user regardless of whether it has the [DONT_REQ_PREAUTH](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties) flag enabled or not, such behavior will lead to an AS-REP Roasting type attack.
---
**So, what happens now?**
Below are the sequential steps that occur until the user’s home screen is loaded:
- <span id="2">**Authentication**: The Client has now obtained the KRB_AS_REP packet, consequently the LSASS process (or rather its SSP that established the connection, namely "Kerberos.dll") performs the decryption of the portion of the KRB_AS_REP packet encrypted with the NT Hash of the domain account performing the authentication (this is because the Client intrinsically knows this value); if this activity is done correctly it means that the authentication has succeeded and for this reason the Kerberos AUTHENTICATION process ends.
> It should be noted that the Client stores in memory the TGT Ticket received, this is the reason why if an attacker compromises this machine, they are able to perform a Pass-The-Ticket (PtT).
- <span id="4">**Authorization**: The Client now needs to understand if the domain account authenticated via Kerberos has the authorizations to access, [in order to do this](https://syfuhs.net/what-happens-when-you-type-your-password-into-windows), it should retrieve the information of the authenticated account by inspecting the "PAC" contained in the received TGT Ticket, but, unfortunately, the PAC contained within the received TGT Ticket is inaccessible since the TGT Ticket is encrypted with the "krbtgt" hash, consequently, similarly to what happens in a Network Logon scenario ([as we will see later](#kerberos-flow---network-logon)), also in this Interactive Logon case, the Client will request a TGS Ticket BUT indicating in the dedicated field an [SPN of type "HOST"](https://en.hackndo.com/service-principal-name-spn/#edge-case---host) related to the Client machine (ex: HOST\Workstation01") involved, since (1) the service account associated with the Client (ex: Workstation01) is its corresponding ["Computer Account"](#relationship-between-a-spn--computer-account) (ex: DOMAIN\Workstation01$), it will be possible to decrypt the TGS Ticket, extract the PAC and perform the authorization verification:

  1. **First Authorization Phase**:The SSP "kerberos.dll" (so the Client) will send a KRB_TGS_REQ packet to the DC in order to request a TGS Ticket; instead of indicating an SPN of a target service ([as we will show later in the context of Network Logon](#kerberos-flow---network-logon)) it will indicate the "HOST" SPN related to the Client machine itself, so where the authentication has just taken place (ex: "HOST\Workstation01"); in this way the DC will respond with a KRB_TGS_REP containing a TGS Ticket encrypted with the Client’s domain account "Computer Account" (ex: DOMAIN\Workstation01$), since the LSASS process of the Client has in memory (specifically in the [LOGON SESSION](https://learn.microsoft.com/en-us/windows/win32/secauthn/lsa-logon-session)) the NT Hash of every Security Principal (every authenticated account) of the machine, including also its own ["Computer Account"](#relationship-between-a-spn--computer-account) (ex: DOMAIN\Workstation01$), it will use the NT Hash of such domain account to decrypt the TGS Ticket and then extract in plaintext the PAC contained within it (the PAC is simply "signed" by the DC with the "krbtgt hash", not encrypted) with which it will perform the analysis related to authorizations.

    > The reason why this step is NOT usually described in a Kerberos authentication articles, is that the Kerberos authentication flow is often captured (from a Windows machine) by [sniffing the network traffic with Wireshark after performing a "klist purge"](#35) (by removing the TGT Ticket, the Client during a Kerberos authentication will necessarily have to re-perform a complete Kerberos authentication); with this procedure, this specific step will NOT be executed because the domain account since is already authenticated on the Client, the Client will NOT need to perform again the AUTHORIZATION check and for this reason it will NOT send this packet during the sniffing.

  2. **Second Authorization Phase**: Another component of the LSASS process will compare the content of the PAC (SID, Group & etc. related to the domain account logged on to the Client) just extracted against the Client’s ACLs and, if positive, the AUTHORIZATION phase performed by the Client will end.

**If positive**:

1. The SSP "Kerberos.dll" (so the LSASS process) creates a LogonSession ([it is a data structure present in LSASS](https://learn.microsoft.com/en-us/windows/win32/secauthn/lsa-logon-sessions)) which will represent the domain account just authenticated (ex: ASTRO\Cosmo)

2. Targetting the LogonSession of the user (e.g, ASTRO\Cosmo) just created, Windows (this action is not performed by Kerberos.dll) will associate to it all the previously loaded SSPs (even if only "kerberos.dll" was actively used for the authentication phase in this context), these SSPs, [as already mentioned](#6), will contain the authenticated user’s credentials in plaintext; this happens to ensure Network Logon SSO functionality (Kerberos or NTLM) since these network protocol requires the use of the current account’s NT Hash (which is derivable from the plaintext password).

    This means that if an attacker is able to dump this Logon Session, they will see all the associated SSPs along with their stored credentials in plaintext (generally speaking since exist some feature that mitigate this logic); that said in reality the MSV SSP (1, 2) will instead provide the NT Hash of the password (dumpable with [sekurlsa::logonpasswords](https://adsecurity.org/?page_id=1821))

3. <span id="10">The SSP "Kerberos.dll" (so the LSASS process) caches the TGT Ticket + TGS Session key inside the Logon Session of the authenticated account (ex: ASTRO\Cosmo) (dumpable with [sekurlsa::tickets](https://adsecurity.org/?page_id=1821))

4. The SSP "Kerberos.dll" (so the LSASS process) caches a hashed version (MSCACHEV2/MSCASH hashes) of the password of the authenticated account (ex: ASTRO\Cosmo) inside the Domain Credential Cached (DCC) (dumpable [lsadump::cache](https://adsecurity.org/?page_id=1821))

  >Since Logon Sessions are created and destroyed dynamically based on user logins and logoffs, an attacker could obtain the NT Hash of a user account (local or domain) only if it is currently logged on (or recently logged on) by dumping the corresponding Logon Session (sekurlsa::logonpasswords) (because the Logon Session still exists inside the memory); the same principle applies also to all the others secrets stored in the Logon Session like for example dumping the Kerberos tickets (sekurlsa::tickets).

5. The domain user (e.g ASTRO\Cosmo) **finally** loads the home screen
Since the TGT Ticket and the TGS Session Key have been cached, if a Network Logon attempt occurs Kerberos will be used again.
If a domain user already logged on to the Client (using Kerberos) needs to authenticate to a target network service and thus perform a "Network Logon" type login, since the Kerberos protocol is SSO (Single Sign On), the following steps are followed.

---

## **Kerberos Flow - Network Logon**

3. ### **KRB_TGS_REQ: The Client provides the KDC with its TGT Ticket to request the TGS Ticket**
Now that a domain user has already authenticated to a Client (using Kerberos) and already possesses the TGT Ticket with a TGS Session Key, if they need to perform a "Network Logon" type login, the Kerberos protocol comes into play again, specifically the Client will use the TGT ticket and the TGS Session Key to request another type of ticket called the TGS Ticket.

> The TGS Ticket has been called this way in many publications because it is issued by the Ticket-Granting Services feature (of the DC) which has the acronym TGS, which, [as already mentioned](#7), for simplicity of explanation in these diagrams instead of specifying that the TGS is issued by the Ticket-Granting Services, it was simply said to be issued by the KDC; that said, in the relevant [RFC4120](https://datatracker.ietf.org/doc/html/rfc4120/) it is understood that the real name of the TGS Ticket is Service Ticket (ST), this is the reason why in other publications ([1](https://zer1t0.gitlab.io/posts/attacking_ad/#st), [2](https://redsiege.com/wp-content/uploads/2020/09/SIEGECAST-KERBEROS-AND-ATTACKS-101.pdf)) this type of Ticket is referred to by this other name.

The Client presents to the KDC (no longer to the AS functionality) a KRB_TGS_REQ which essentially contains:

<span id=13>{{< image src="/not_so_brief_overview_about_kerberos/krb_tgs_req.png" position="center" style="border-radius: 8px;" >}}

- **Ticket TGT**: The [previously received](#8) TGT ticket.
  > It has never been decrypted, is sent to the client encrypted as obtained previously, that is, encrypted with the "krbtgt hash".
- **Authenticator**: Username (domain user who made the request) & Timestamp, both encrypted with the TGS Session Key (obtained with KRB_AS_REP [which was decrypted and cached previously during the Interactive Logon operation](#10).

- <span id=16> **SPN**: The SPN related to / pointing to the service the Client needs to connect to via SSO is sent in plain-text, such as the SPN "HTTP/Charlotte.medin.local" or "CIFS/SERV01" (1); in the first, one wants to authenticate to the HTTP service present on the Hostname "Charlotte.medin.local" while in the second to the CIFS service present on the Hostname SERV01.

<span id=18>I want to highlight that both TGT Ticket & TGS Ticket (also called Service Ticket / ST ) both contain the [Privilege Attribute Certificate (PAC)](#privilege-attribute-certificate-pac), that is, a data structure used by the Kerberos protocol to share with the other actors involved in the authentication the security information related to the domain user attempting the login, including: Username, ID, Group Membership and in general all security information; [the PAC is NOT encrypted but ONLY signed](#11).

4. ### **KRB_TGS_REP: KDC sends the TGS Ticket to the client**

The KDC, after having received the packet from the Client, being in possession of the "krbtgt hash" decrypts the received TGT Ticket and extracts the TGT Owner (["username" field of the TGT](#12)) & the related [TGS Session Key](#12), then it uses such extracted TGS Session Key to decrypt the Authenticator received in that packet ([KRB_TGS_REQ](#13)), if everything goes well and the "Username" field (contained in [KRB_TGS_REQ](#13)) matches the TGT Owner (["username" field of the TGT Ticket](#12)) and the timestamp is valid, then the KDC verifies whether the PAC contained in the received TGT Ticket is valid (the KDC, having the krbtgt hash, computes a signature on the content of the PAC to verify if such output [matches the signature present in the PAC of the TGT Ticket](#15)) and if positive generates the TGS Ticket (Service Ticket / ST); in this way the KDC (DC) has ensured that whoever has made the request for a TGS Ticket has a TGT Ticket with a valid related TGS Session Key and that the PAC is correct.
  
Once the verification is completed, the KDC sends to the Client the KRB_TGS_REP packet containing:

<span id=19>{{< image src="/not_so_brief_overview_about_kerberos/krb_tgs_rep.png" position="center" style="border-radius: 8px;" >}}

- <span id=29>**Ticket TGS**: TGS Ticket encrypted with the hash of the service account related to the service that the client wishes to access (called in the image "Service Owner Hash"), it has been retrieved [using the SPN field configured in the KRB_TGS_REQ packet](#16); for example, if via Kerberos SSO ([Page 15](https://redsiege.com/wp-content/uploads/2020/09/SIEGECAST-KERBEROS-AND-ATTACKS-101.pdf)) we requested the SPN "HTTP/Charlotte.medin.local", the password of the service account associated with that HTTP service (e.g., DOMAIN\websvc) will be used to encrypt the TGS Ticket, if instead the request was made to the SPN "MSSQL/db01.medin.local", the password of the service account associated with that MSSQL service (e.g., DOMAIN\sqlengine) will be used to encrypt the TGS Ticket; another scenario is if the request is made, for example, to the SPN "CIFS/serv01" (one of the several services usually run with the "[Local Service Account](https://learn.microsoft.com/it-it/windows/win32/services/localservice-account?redirectedfrom=MSDN)" - so a [Default Local System Account](https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts#default-local-system-accounts)), in this case as well the password of the related Service Account ([so the Computer Account "serv01$"](#17)) will be used to encrypt the TGS Ticket.

> The KDC, being the DC, knows the hashes of all domain users, so also the service accounts (which are domain users) and also the hash of the service account that runs the service requested by the Client.

> The PAC of the TGS Ticket is a copy of the PAC contained in the [received TGT Ticket](#12).

- **Other Data**: A "Service Session Key", together with other data, encrypted with the TGS Session Key; it will be used as the encryption key for the final packet exchanges.
As [already mentioned](#18), the TGS Ticket (also called Service Ticket), like the TGT Ticket, contains the PAC (Privilege Attribute Certificate), that is, a structure contained in every ticket which holds the characteristics of the user (SID, group, etc.); furthermore, it must be specified that the PAC is NOT encrypted but signed.

5. ### **KRB_AP_REQ: The Client attempts to access the AP resource by providing its TGS Ticket**

<span id=23>The Client decrypts the portion of the [KRB_TGS_REP](#19) packet received using the TGS Session Key that the Client had previously received with the [KRB_AS_REP packet](#9) and [cached during the Interactive Login phase](#10), by decrypting it obtains the plaintext value of the "Service Session Key", which will be used as the key for this exchange between the Client and the AP.
  
If everything has gone well, the user now has a valid TGS Ticket to use in order to access the target service, once the verification is completed, the actions are:

<span id=26>{{< image src="/not_so_brief_overview_about_kerberos/krb_ap_req.png" position="center" style="border-radius: 8px;" >}}
- **Ticket TGS**: The Client sends a packet containing the TGS Ticket (Service Ticket / TS) (which had already previously been encrypted with the hash of the service account of the target service) to the AP.

- **Authenticator**: The packet contains an "Authenticator" (Username + Timestamp) encrypted with the [Service Session Key, so with the key just extracted](#23).
For synthesis reasons it was **NOT** reported in the image but in reality in the KRB_AP_REQ packet the "SPN" field is sent again, in this way [subsequently](#1) the AP will know which service account hash to retrieve in order to decrypt the TGS Ticket to perform the verification.

---

**So, again, what happens now?**

The AP, after having received the KRB_AP_REQ packet from the Client, performs the following actions:

- <span id="1">**Authentication**: The AP, having at its disposal the NT Hash of the service account the Client wishes to authenticate to, uses it to decrypt the received TGS Ticket and extracts the PAC & the TGS Owner ("[username field" of the TGS](#19)) & the "[Service Session Key](#19)". The AP uses this "Service Session Key" just extracted to decrypt the Authenticator received in the [KRB_AP_REQ](#26) packet, if everything goes well and the "Username" field of the Authenticator ([contained in KRB_AP_REQ](#26)) matches the TGS Owner ("[username field" of the TGS](#19)) and the timestamp is valid, the "AUTHENTICATION" phase of the Kerberos protocol is completed.

  >It should be noted that the AP stores the received TGS Ticket in memory, this is the reason why if an attacker compromises that machine, they are able to perform a Pass-The-Ticket (PtT).

- <span id="3">**Authorization**: The AP uses the PAC [just extracted](#1) from the TGS Ticket (Service Ticket / ST) and uses it to determine whether the domain user in question actually has the permissions to access the service, specifically, since the PAC contains in plain-text ([page 13](https://redsiege.com/wp-content/uploads/2020/09/SIEGECAST-KERBEROS-AND-ATTACKS-101.pdf)) (the PAC is simply "[signed](#11)" by the DC with the "krbtgt hash", not encrypted) the security information of the domain user who needs to connect to the service, such as SID, Username, RID and other data, the AP compares this information with the ACLs related to the service, if the outcome is positive the AP will grant the Client access to the service and this **finaly** concludes the "AUTHORIZATION" phase which I highlight is carried by the AP, so by the service.

As can be seen, the Kerberos protocol validates to the target service (e.g. CIFS/SMBSERVER01) that the domain user who requested access is authenticated and valid ([AUTHENTICATION](#1)), while it's the target service itself (e.g. CIFS/SMBSERVER01), or rather the server hosting that service, namely the AP, that is responsible for verifying whether that user has the necessary permissions to access that service ([AUTHORIZATION](#3)).

Due to how the Kerberos protocol works, the AP (the server hosting the service such as CIFS to which the domain user needs to authenticate) will NEVER receive the NT Hash of the domain user who authenticated, because the AP will only receive the KRB_AP_REQ packet which does not contain such data, this means that if an attacker exploits the AP, from it they will not be able to recover the domain credentials of the users who have connected via SSO to that service.

---
<span id=33>**Optional**

Although it is not the Kerberos protocol itself but the [NRPC (NetLogon) protocol](https://www.tarlogic.com/blog/how-kerberos-works/) ([1](https://adsecurity.org/?p=1515)), if the AP needs to verify whether the PAC received ([contained in the TGS Ticket](#26)) is valid, [a checks that it does not happen often](#28), it can verify it by sending a packet named [KERB_VERIFY_PAC_REQUEST](https://learn.microsoft.com/en-us/archive/blogs/openspecification/understanding-microsoft-kerberos-pac-validation#kerberos-pac-validation) as indicated later; furthermore, if the Client explicitly requests it ([flag "ap-options=1"](https://datatracker.ietf.org/doc/html/rfc1510#section-5.5.1) inside the [KRB_AP_REQ packet](#26)), the AP must also authenticate itself to the Client, this concent is called "Mutual Authentication"; if both activities are required, the following steps 6, 7, and 8 will take place, and only after their completion the AP (or rather its service) will grant access to the Client.

> <span id=28>I want to highlight that the PAC contained in the TGT Ticket is ALWAYS validated (when the DC receives the KRB_TGS_REQ) while the PAC contained in the TGS Ticket is validated ONLY if properly configured (by configuring a registry which is disabled by default).
In the case where both the PAC verification and the Client request for Mutual Authentication are present, the following steps occur:

  6. ### **(Optional) KERB_VERIFY_PAC_REQUEST** 
  
  In the case where the service (AP) wants to validate whether the PAC received (contained in the TGS Ticket) is valid, it uses the Netlogon protocol [to ask the DC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-apds/b27be921-39b3-4dff-af4a-b7b74deb33b5) to verify the PAC signature.
  
  7. ### **(Optional) PAC_RESPONSE**
  
  The DC will verify if the PAC is valid (for simplicity of explanation, we can say that the DC will calculate a "signature" on the PAC content and if this output matches the existing signature, then the PAC will be considered valid) and will respond with a code indicating if it is correct; this packet representing the response has no specific name, it is simply called "[PAC RESPONSE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-apds/b27be921-39b3-4dff-af4a-b7b74deb33b5)".
  
  8. ### **(Optional) KRB_AP_REP**
  
  Finally, optionally, if the Client explicitly requests it, even the service itself (and NOT the related service account), so the AP, must authenticate itself performing a so-called "mutual authentication"; to do this, instead of contacting the AD, the AP responds directly to the Client by sending a [KRB_AP_REP](https://datatracker.ietf.org/doc/html/rfc4120#section-5.5.2) (as a response to the previous KRB_AP_REQ) [containing a TIMESTAMP encrypted](https://datatracker.ietf.org/doc/html/rfc4120#section-5.5.2) with the "[Service Session Key](#19)"; if the Client correctly decrypts the TIMESTAMP with the "Service Session Key" it possesses (the Client has the legitimate "Service Session Key" because it received it from the DC in the [KRB_TGS_REP](#19)), then it is demonstrated that the AP, having the correct "Service Session Key", is legitimate (this is because the AP, to have this legitimate "Service Session Key", would have had to extract the data from the TGS received from the Client - KRB_AP_REQ - which was encrypted with the "[Service Owner Hash](#29)", information that only the legitimate AP should know); in other words, [in this way the Client is sure it is connecting to the original service](https://www.educative.io/blog/kerberos-in-5-minutes#) and not to another service of a potential attacker pretending to be the original service.

## **Privilege Attribute Certificate (PAC)**

### **What's a Privilege Attribute Certificate (PAC)?**

[As already mentioned](#18), the [Privilege Attribute Certificate (PAC)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/166d8064-c863-41e1-9c23-edaaa5f36962) is a data structure that uses the Kerberos protocol to share with the other actors involved in the authentication, the security information related to the domain account attempting the login, including: Username, ID, Group Membership, and in general all security information.

The PAC is particularly important as it is used during the AUTHORIZATION phase (I want to remind that it is not managed by the Kerberos protocol) respectively either by the Client in an [Interactive Logon](#kerberos-flow---interactive-login) or by the AP / Remote Service in a [Network Logon to](#kerberos-flow---network-logon) understand if the domain account can access the service or not.

The PAC is contained inside the both types of Kerberos Tickets TGT & TGS (in the "authorization-data" field), consequently the PAC is indirectly encrypted with the "krbtgt" account hash in the first case (TGT Ticket) or indirectly encrypted with the service account hash against which the authentication is performed in the second case (TGS Ticket).

Below there is an image that shows the content of a PAC within a TGS Ticket:

{{< image src="/not_so_brief_overview_about_kerberos/PAC.png" position="center" style="border-radius: 8px;" >}}

A traditional account performing Kerberos authentication, NOT knowing the hash to decrypt the TGT Ticket or the hash to decrypt the TGS Ticket, it means that the PAC could not be readable by a traditional user.

  - **[KDC Signature](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/3122bf00-ea87-4c3f-92a0-91c0a99f5eec)**: "KDC Signature" is a field contained in the PAC that holds a string representing the signature (also called checksum) created by signing the PAC content with the secret of the "krbtgt" account (default service account of the KDC).

<span id=11>Furthemore, i want to highlight that the PAC entity itself is issued by the DC in a "signed" way (not encrypted), meaning that inside it there will be several fields containing the signatures (checksums) calculated on the PAC content with a specific "key"; these signatures contained inside the PAC can potentially be used to verify the integrity of the PAC it self, below we see [briefly](https://trustedsec.com/blog/red-vs-blue-kerberos-ticket-times-checksums-and-you)([1](https://www.youtube.com/watch?t=871&v=Jaa2LmZaNeU&feature=youtu.be&themeRefresh=1)) what types of signatures it possesses:
**Ticket TGS**:

- **[Server Signature](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/a194aa34-81bd-46a0-a931-2e05b87d1098)**: "Server Signature" is a field contained in the PAC that holds a string representing the signature (also called checksum) calculated by signing the PAC content with the secrets of the service account against which authentication is attempted.
  
- **[KDC Signature](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/3122bf00-ea87-4c3f-92a0-91c0a99f5eec)**: "KDC Signature" is a field contained in the PAC that holds a string representing the signature (also called checksum) created by signing the PAC content with the secret of the "[krbtgt](https://www.tarlogic.com/cybersecurity-glossary/krbtgt/)" account (default service account of the KDC).
  
> This signature is the one that could be checked inside a TGS Ticket to prevent a Silver Ticket BUT as this is [NOT](https://zer1t0.gitlab.io/posts/attacking_ad/#pac) done.

<span id=15> **Ticket TGT**:
  - **[KDC Signature](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/3122bf00-ea87-4c3f-92a0-91c0a99f5eec)**: "KDC Signature" is a field contained in the PAC that holds a string representing the signature (also called checksum) created by signing the PAC content with the secret of the "[krbtgt](https://www.tarlogic.com/cybersecurity-glossary/krbtgt/)" account (default service account of the KDC).
  
In reality the TGT Ticket also has a field dedicated to the "Server Signature" but having no meaning, since it is the TGS Ticket that is used to authenticate to services and not the TGT Ticket, a "symbolic" value will be present there which will have no relevance.

## **Kerberos Keys**

### **What's a Kerberos Key?**

As already seen, the Kerberos protocol allows the user to request a TGT Ticket from the Domain Controller by sending a KRB_AS_REQ encrypting the "Timestamp" field with the NT Hash of the account performing the authentication, if it is correct everything proceeds properly, that said, in reality, the Kerberos protocol also more generically accepts the entity called "Kerberos Keys".

When a domain account is created, the Domain Controller will take as input the corresponding plain-text password and encrypt it using different algorithms, the output of these will be the entity called "Kerberos Keys":

  - **AES 256 Key**: "AES 256 Key" is the output of the plain-text password using the "[AES256_HMAC_SHA1](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos)" algorithm.
  
    This "AES 256 Key" is the Kerberos Key most commonly used by the Kerberos protocol, consequently an attacker using this Key instead of others will be able to bypass detection tools more easily.
  
  - **AES 128 Key**: "AES 128 Key" is the output of the plain-text password using the "[AES128_HMAC_SHA1](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos)" algorithm.
  
  - **DES Key (DES_CBC_MD5)**: "DES Key" is the output of the plain-text password using the "[DES_CBC_MD5](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos)" algorithm.
  
  - **RC4 Key**: "RC4 Key" is the output of the plain-text password using the now deprecated "[RC4_HMAC_MD5](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos)" algorithm.
  
    This "RC4 Key" is nothing more than the NT Hash of the domain account password, consequently, being synonyms, it means that the term "NT Hash" used during the explanation of the Kerberos protocol is nothing more than the "RC4 Key".

An attacker is able to retrieve the Kerberos Keys for example by dumping the "[NTDS.dit](https://www.semperis.com/blog/ntds-dit-extraction-explained/)" file from the Domain Controller, below there is an example using the [Secretsdump](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) utility:

{{< image src="/not_so_brief_overview_about_kerberos/kerberos_key_1.png" position="center" 
style="border-radius: 8px;" >}}

In the section indicated above, the "RC4 Keys" are NOT present because as the tool for semplicity places them in the section dedicated to the NT Hash of the domain accounts.

{{< image src="/not_so_brief_overview_about_kerberos/kerberos_key_2.png" position="center" 
style="border-radius: 8px;" >}}

If an attacker manages to obtain a Kerberos Key of a victim account, they would be able to impersonate it in a Kerberos authentication using an attack called "Pass-The-Key".

## **Service Principal Name (SPN)**

### **What's a Service Principal Name (SPN)?**

A "[Service Account](https://en.wikipedia.org/wiki/Service_account)" is nothing more than an account created and used for the start & running of a specific service, furthermore, if this service needs to interact with other services it can do it using its own "Service Account".

In a classic scenario when the local or domain user "BOB" starts the software "Notepad" application, the operating system runs "Notepad" using the account "BOB", when a Service Account is used, instead, the OS will start the service (for example MMSQL) using that specific Service Account, this will mean that viewing the running processes though Task Manager it will be possible to see that the service "Microsoft SQL" is running with the related "Service Account".

One type of "Service Account" are the "[Standard Service Account](https://learn.microsoft.com/en-us/windows/win32/services/service-user-accounts)", so "Service Accounts" that do NOT have passwords and they are used by Windows OS to start specific services usually system-related, the most common example is the "[NetworkService Account](https://learn.microsoft.com/it-it/windows/win32/services/networkservice-account?redirectedfrom=MSDN)" which is usually used to start the IIS or MSSQL Server service.

<span id=30>A [Service Principal Name (SPN)](https://learn.microsoft.com/en-us/windows/win32/ad/service-principal-names) is a unique identifier of a service instance, SPNs are used by Kerberos authentication to associate the service instance (the start & running of the service, for example Microsoft SQL) with a "Logon Account" (which it will become Service Account); in other words, (generically speaking) an SPN can be considered as a generic object that represents the association between a service and a domain account, that said, technically, [it is an attribute of the "Users" object](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772815(v=ws.10)#service-principal-names).

<span id=31>"Standard Service Accounts" by definition are NOT "Logon Accounts" since they are used exclusively by the operating system and do NOT have passwords.

This essentially means that through an SPN it is possible to map the start & running of a service on a server to a domain account rather than associating it with a "Standard Service Account" such as the NetworkService Account
Each service (hosted on a server joined into a domain) that wants a domain user to authenticate to it using the Kerberos protocol (Kerberos SSO) must necessarily have an SPN configured so that the potential "Client" (so the actor involved in Kerberos Authentication) can uniquely identify the service within the network; if no SPN is set for a service, then the Client has NO way to locate the service and consequently the Kerberos authentication is NOT possible.

An SPN (so an attribute of the "user" object) is (usually, it's not mandatorylin) built using the name of the "service class" followed by the hostname that starts the service; finally, optionally, it can also include the port and an arbitrary name to associate:

<span id="target-text2">{{< image src="/not_so_brief_overview_about_kerberos/spn1.png" position="center" 
style="border-radius: 8px;" >}}

For example: A SPN named "DNS/dc01.capsule.corp" rappresent a DNS Service hosted on the DC01.capsule.corp associated with a domain user like "capsule.corp\arbitrary_dnsuser".

Microsoft has documented a (non-exhaustive) list of the so-called "service_class," that is, standard names used to indicate certain types of services; as you can see, the most common are [CIFS, DNS, SPOOLER and WWW](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772815(v=ws.10)#service-principal-names).

### **Relationship Between a SPN & Computer Account**

In a domain scenario, each "person" within the organization will have its own domain user account (so a "Users" object); that said, every computer joined to the domain will also have its own associated domain account, called a "Computer Account" or "Machine Account" ([1](https://itfreetraining.com/lesson/computer-accounts/), [2](https://zer1t0.gitlab.io/posts/attacking_ad/#computer-accounts)) which will be used by the Client itself (or more precisely by the SYSTEM account of the Client) for activities where it needs to interact with other entity joined within the domain, for example checking if it is necessary to update the "Group Policies" (Client -> Domain Controller), [verifying the permissions of a domain account authenticated to the computer with Kerberos and so on](#4).

The difference between a "User" and a "Computer Account" is that even though both are domain user that exists and are registered on the DC, the first is an object of type "[User](https://www.windows-active-directory.com/active-directory-user-objects-management.html)," while the second, that is, the "Computer Account," is instead [a subclass of the "User" class](https://zer1t0.gitlab.io/posts/attacking_ad/#computer-accounts) (so we can say it's a user) BUT it is stored within a "Computer" object.

The following command queries the DC and requests to print on screen all the domain accounts that exists in the AD; as you can see, in addition to the Administrator account, there are: the nominal account (tstark, fcastle, pparker), the service account (SQLService) and 3 other accounts indicated with a $ at the end of the syntax, those are the "Computer Accounts"; all "Computer Accounts" (or "Machine Accounts") have as their name the associated hostname and end with the $ sign.

{{< image src="/not_so_brief_overview_about_kerberos/spn2.png" position="center" 
style="border-radius: 8px;" >}}

Consequently, "HYDRA-DC$" is the "Computer Account" of the Domain Controller HYDRA-DC, "THEPUNISHER$" is the "Computer Account" of the Client THEPUNISHER, and finally "SPIDERMAN$" is the "Computer Account" of the Client SPIDERMAN.

<span id=34>A "Computer Account" (Machine Account), unlike a traditional domain user, is automatically generated by the DC when the computer is joined to the domain; specifically, the computer itself randomly ([120 characters](https://zer1t0.gitlab.io/posts/attacking_ad/#kerberoast)) creates the password (and then shares it with the DC) and by default it will use the machine’s hostname followed by a $ for the creation of the name; that said, the password of the domain account "Computer Account" is instead changed [by default](https://adsecurity.org/?p=280) (this timing is configurable - [1](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396026), [2](https://zer1t0.gitlab.io/posts/attacking_ad/#lsa-secrets)) every 30 days.

In addition to the existence of SPNs that allow associating a domain user (becoming a Service Account in this scenario) with a specific service, so by setting a specific "Service Class" such as CIFS or others, there is also a SPNs of type "HOST".

Technically, [as previously told](#30), an SPN was created with the purpose of associating a service with a Service Account (domain user), a SPN of type HOST is the exception to this rule since the keyword "HOST" is NOT a service but directly represents the whole "computer" object itself, in order to associate a whole "Computer" object with a Service Account via SPN, in reality a trick is used, essentially the keyword HOST in order to represent the whole machine but having to necessarily specify a service, the "HOST" Service Class is an ALIAS ([1](https://en.hackndo.com/service-principal-name-spn/#edge-case---host), [2](https://learn.microsoft.com/en-us/windows/win32/adschema/a-spnmappings)) that groups together all the possible [Service Class](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772815(v=ws.10)#service-principal-names) of an SPN such as CIFS, WWW, DNS etc, subsequently it was defined that the Service Account that can be associated with the "Computer" object (which indirectly holds the Host SPN) via SPN is its corresponding "Computer Account", in other words, for example: The SPN "HOST\Workstation1" links the Computer object "Workstation1" to the Service Account "Workstation1$" (which is a Computer Account).

<span id=17>Finally, it should be specified that if a service is run on a computer with a "Standard Service Account" (for example Local System / NetworkService Account), such as by default the CIFS / LDAP services, if these services need to use the Kerberos protocol (for example they accept a Kerberos domain authentication) the computer will use the "Computer Account" of the machine that host these services as their Service Account (in this scenario the "secrets" of the Computer Account will be used to encrypt the TGS Ticket); this happens because the "Standard Service Account" (ex Local System / NetworkService Account) [exists only in a local context](#31).

## **Inspect the Kerberos yourself!**

Now that the theory has been explained i recommend moving on to practice!

<span id=35>For educational purposes i recommend creating your own personal lab, there are several resources online that detail [how to do this](https://www.youtube.com/watch?v=xftEuVQ7kY0), once this has been done, it will be possible to use WireShark to analyze the traffic started from a Kerberos authentication, to see the whole process we can for example run the command "klist purge" (which removes all the Cached Kerberos Tickets) on a domain joined Windows machine and perform a Network Logon authentication to another machine within the network, for example via SMB, if you have do this you will see all the Kerberso traffic generated.

{{< image src="/not_so_brief_overview_about_kerberos/kerberos_wholeflow.png" position="center" 
style="border-radius: 8px;" >}}

As you can see with the following traffic has been generated:

  1. KRB_AS_REQ
  
  The reason why the 2 "KRB_AS_REQ" packets were sent [has been previously analyzed.](#32)

  2. KRB_AS_REP
  3. KRB_TGS_REQ
  4. KRB_TGS_REP
  
In this scenario, only "[Mutual Authentication](#33)" is enabled:

  5. KRB_AP_REQ: The Kerberos packet "KRB_AP_REQ" is encapsulated within the packet related to the protocol used by the service hosted by the AP, in this case it's SMB.
  
- KRB_AP_REP: Since "Mutual Authentication" is enabled, the AP will respond to the Client with a KRB_AP_REP, always embedding it in this example inside the SMB protocol.

### **How to decrypt Kerberos traffic**

As previously analyzed, some portions of the Kerberos packets will be encrypted with the krbtgt account secrets (TGT Ticket) or with the Service Account secrets related to the service hosted by the AP (TGS Ticket), to be able to analyze everything in plain-text it's necessary to properly configure Wireshark, specifically it is possible to provide Wireshark with a "[keytab](https://web.mit.edu/kerberos/krb5-devel/doc/basic/keytab_def.html)" file containing ALL the secrets (NT Hash & [Kerberos Key](#kerberos-keys)) related to the entities involved in Kerberos authentication, in this way Wireshark will be able to decrypt the part.

> [As already explained](#34), since by default the DC changes the password of ALL Computer Accounts every 30 days, if this behavior is not disabled / modified, the operation will need to be repeated periodically.

To do this, one can perform a DCSync on the Domain Controller and retrieve the NT Hashes, AES-256 Kerberos Key, and AES-128 Kerberos Key of each involved "Principal" (Domain Users & Computer Accounts & krbtgt user), then insert these values into the dedicated section in the "[keytab.py](https://github.com/dirkjanm/forest-trust-tools/blob/master/keytab.py)" script and finally execute the script to generate the "keytab.kt" file:

- Dump the "secrets" (perform a DCSync).

  {{< image src="/not_so_brief_overview_about_kerberos/dcsync.png" position="center" 
style="border-radius: 8px;" >}}

- Populate the "[keytab.py](https://github.com/dirkjanm/forest-trust-tools/blob/master/keytab.py)" script.

  {{< image src="/not_so_brief_overview_about_kerberos/keytab1.png" position="center" 
style="border-radius: 8px;" >}}

- Execute the "keytab.py" script to generate the "keytab.kt" file.

  {{< image src="/not_so_brief_overview_about_kerberos/keytab2.png" position="center" 
style="border-radius: 8px;" >}}

Once this is done, go to Wireshark and navigate to "Edit -> Preferences -> Protocols -> KRB5", select the file and check the box "Try to decrypt Kerberos blob".

{{< image src="/not_so_brief_overview_about_kerberos/keytab3.png" position="center" 
style="border-radius: 8px;" >}}

Once everything is done, all the encrypted Wireshark traffic that has been correctly decrypted will be highlighted in blue, while if the decryption has failed it will be highlighted in yellow:

{{< image src="/not_so_brief_overview_about_kerberos/keytab4.png" position="center" 
style="border-radius: 8px;" >}}

## **Outro**

The Kerberos protocol is a beast to understand and we have only scratched its surface, with this article i hope to have clarified its basic behavior, if you notice any inaccuracies or want to ask me something, do not hesitate to write to me!

## **References**

- https://stealthbits.com/blog/what-is-kerberos/
- https://www.tarlogic.com/en/blog/how-kerberos-works/
- https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-accounts#krbtgt-account
- https://www.devadmin.it/2020/07/27/account-krbtgt-e-best-practices-di-sicurezza/
- https://www.educative.io/blog/kerberos-in-5-minutes
- https://redsiege.com/wp-content/uploads/2020/09/SIEGECAST-KERBEROS-AND-ATTACKS-101.pdf
- https://www.crowdstrike.com/cybersecurity-101/ntlm-windows-new-technology-lan-manager/
- https://en.hackndo.com/kerberos/
- https://learn.microsoft.com/en-us/archive/blogs/openspecification/
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/b4af186e-b2ff-43f9-b18e-eedb366abf13
- https://syfuhs.net/what-happens-when-you-type-your-password-into-windows
- https://swarm.ptsecurity.com/kerberoasting-without-spns/
- https://labs.lares.com/fear-kerberos-pt1/#preauth
- https//www.chudamax.com/posts/kerberos-102-overview/
- https://en.hackndo.com/kerberos-silver-golden-tickets/#pac https://zer1t0.gitlab.io/posts/attacking_ad/#pac
- https://trustedsec.com/blog/red-vs-blue-kerberos-ticket-times-checksums-and-you
- https://labs.lares.com/author/raul/
- https://zer1t0.gitlab.io/posts/attacking_ad/#user-kerberos-keys
- https://www.thehacker.recipes/ad/movement/kerberos/ptk
- https://en.wikipedia.org/wiki/Service_account 
- https://learn.microsoft.com/en-us/windows/win32/ad/service-principal-names
- https://malicious.link/posts/2016/kerberoast-pt1/
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772815(v=ws.10)#service-principal-names
- https://en.hackndo.com/service-principal-name-spn/#edge-case---host
- https://zer1t0.gitlab.io/posts/attacking_ad/#computer-accounts

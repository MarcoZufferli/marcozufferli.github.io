---
title: "Demystify Kerberos Delegation Attacks"
date: 2025-09-16T14:56:19+02:00
draft: true
toc: true
---

# Kerberos Delegation Attacks

## Abuse Unconstrained Delegation (Computer)
### Abuse Unconstrained Delegation (Computer) (1 method)
### Abuse Unconstrained Delegation (Computer) (2 method)
### Abuse Unconstrained Delegation (Computer)- Detect & Mitigation
## Abuse Protocol Transition
### Abuse Protocol Transition - Windows
### Abuse Protocol Transition - Linux
### Abuse Protocol Transition - Detect & Mitigation
## Abuse RBCD via DACL
### Abuse RBCD via DACL - Windows
### Abuse RBCD via DACL - Linux
### Abuse RBCD via DACL - Detect & Mitigation
### Abuse Protocol Transition - Detect & Mitigation
## Abuse Kerberos Only
### Abuse Kerberos Only - Windows
### Abuse Kerberos Only - Detect & Mitigation


TEST - x dopo 

### 1. KRB\_TGS\_REQ: The Client provides its own TGT Ticket to the KDC to request the TGS Ticket.
### 2. KRB\_TGS\_REP: The KDC sends the TGS Ticket to the Client BUT specifying that the requested service has the Kerberos Unconstrained Delegation enabled.
### 3. KRB\_TGS\_REQ: The Client requests a "Ticket TGT Forwarded" from the KDC.
### 4. KRB\_TGS\_REP: The KDC sends a "Ticket TGT Forwarded" to the Client.
### 5. KRB\_AP\_REQ: The Client attempts to access the Front-End AP by providing its own TGS Ticket BUT also sharing the so-called "Ticket TGT Forwarded".
### 6. KRB\_TGS\_REQ: The Front-End AP provides the Client’s "Ticket TGT Forwarded" to the KDC to request a TGS Ticket.
### 7. KRB\_TGS\_REP: The KDC sends the TGS Ticket to the Front-End AP.
### 8. KRB\_AP\_REQ: The Front-End AP presents the TGS Ticket to the Back-End AP to authenticate on behalf of the Client.)
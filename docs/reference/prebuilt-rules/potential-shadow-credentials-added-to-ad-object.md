---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-shadow-credentials-added-to-ad-object.html
---

# Potential Shadow Credentials added to AD Object [potential-shadow-credentials-added-to-ad-object]

Identify the modification of the msDS-KeyCredentialLink attribute in an Active Directory Computer or User Object. Attackers can abuse control over the object and create a key pair, append to raw public key in the attribute, and obtain persistent and stealthy access to the target user or computer object.

**Rule type**: query

**Rule indices**:

* winlogbeat-*
* logs-system.*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials](https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials)
* [https://github.com/OTRF/Set-AuditRule](https://github.com/OTRF/Set-AuditRule)
* [https://cyberstoph.org/posts/2022/03/detecting-shadow-credentials/](https://cyberstoph.org/posts/2022/03/detecting-shadow-credentials/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: Active Directory
* Resources: Investigation Guide
* Use Case: Active Directory Monitoring
* Data Source: System

**Version**: 213

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_771]

**Triage and analysis**

**Investigating Potential Shadow Credentials added to AD Object**

The msDS-KeyCredentialLink is an Active Directory (AD) attribute that links cryptographic certificates to a user or computer for domain authentication.

Attackers with write privileges on this attribute over an object can abuse it to gain access to the object or maintain persistence. This means they can authenticate and perform actions on behalf of the exploited identity, and they can use Shadow Credentials to request Ticket Granting Tickets (TGTs) on behalf of the identity.

**Possible investigation steps**

* Identify whether Windows Hello for Business (WHfB) and/or Azure AD is used in the environment.
* Review the event ID 4624 for logon events involving the subject identity (`winlog.event_data.SubjectUserName`).
* Check whether the `source.ip` is the server running Azure AD Connect.
* Contact the account and system owners and confirm whether they are aware of this activity.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Review the event IDs 4768 and 4769 for suspicious ticket requests involving the modified identity (`winlog.event_data.ObjectDN`).
* Extract the source IP addresses from these events and use them as indicators of compromise (IoCs) to investigate whether the host is compromised and to scope the attacker’s access to the environment.

**False positive analysis**

* Administrators might use custom accounts on Azure AD Connect. If this is the case, make sure the account is properly secured. You can also create an exception for the account if expected activity makes too much noise in your environment.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Remove the Shadow Credentials from the object.
* Investigate how the attacker escalated privileges and identify systems they used to conduct lateral movement. Use this information to determine ways the attacker could regain access to the environment.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_496]

**Setup**

The *Audit Directory Service Changes* logging policy must be configured for (Success, Failure). Steps to implement the logging policy with Advanced Audit Configuration:

```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Policies Configuration >
Audit Policies >
DS Access >
Audit Directory Service Changes (Success,Failure)
```

The above policy does not cover User objects, so we need to set up an AuditRule using [https://github.com/OTRF/Set-AuditRule](https://github.com/OTRF/Set-AuditRule). As this specifies the msDS-KeyCredentialLink Attribute GUID, it is expected to be low noise.

```
Set-AuditRule -AdObjectPath 'AD:\CN=Users,DC=Domain,DC=com' -WellKnownSidType WorldSid -Rights WriteProperty -InheritanceFlags Children -AttributeGUID 5b47d60f-6090-40b2-9f37-2a4de88f3063 -AuditFlags Success
```


## Rule query [_rule_query_819]

```js
event.code:"5136" and winlog.event_data.AttributeLDAPDisplayName:"msDS-KeyCredentialLink" and
  winlog.event_data.AttributeValue :B\:828* and
  not winlog.event_data.SubjectUserName: MSOL_*
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Modify Authentication Process
    * ID: T1556
    * Reference URL: [https://attack.mitre.org/techniques/T1556/](https://attack.mitre.org/techniques/T1556/)




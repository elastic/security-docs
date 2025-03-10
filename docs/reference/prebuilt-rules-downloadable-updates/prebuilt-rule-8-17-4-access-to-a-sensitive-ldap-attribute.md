---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-access-to-a-sensitive-ldap-attribute.html
---

# Access to a Sensitive LDAP Attribute [prebuilt-rule-8-17-4-access-to-a-sensitive-ldap-attribute]

Identify access to sensitive Active Directory object attributes that contains credentials and decryption keys such as unixUserPassword, ms-PKI-AccountCredentials and msPKI-CredentialRoamingTokens.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-system.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.mandiant.com/resources/blog/apt29-windows-credential-roaming](https://www.mandiant.com/resources/blog/apt29-windows-credential-roaming)
* [https://social.technet.microsoft.com/wiki/contents/articles/11483.windows-credential-roaming.aspx](https://social.technet.microsoft.com/wiki/contents/articles/11483.windows-credential-roaming.aspx)
* [https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Credential Access
* Tactic: Privilege Escalation
* Use Case: Active Directory Monitoring
* Data Source: Active Directory
* Data Source: System
* Resources: Investigation Guide

**Version**: 113

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4719]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Access to a Sensitive LDAP Attribute**

LDAP (Lightweight Directory Access Protocol) is crucial for accessing and managing directory information in Active Directory environments. Adversaries may exploit LDAP to access sensitive attributes like passwords and decryption keys, facilitating credential theft or privilege escalation. The detection rule identifies unauthorized access attempts by monitoring specific event codes and attribute identifiers, excluding benign activities to reduce noise, thus highlighting potential security threats.

**Possible investigation steps**

* Review the event logs for event code 4662 to identify the specific user or process attempting to access the sensitive LDAP attributes.
* Check the winlog.event_data.SubjectUserSid to determine the identity of the user or service account involved in the access attempt, excluding the well-known SID S-1-5-18 (Local System).
* Analyze the winlog.event_data.Properties field to confirm which sensitive attribute was accessed, such as unixUserPassword, ms-PKI-AccountCredentials, or msPKI-CredentialRoamingTokens.
* Investigate the context of the access attempt by correlating the event with other logs or alerts around the same timestamp to identify any suspicious patterns or activities.
* Verify the legitimacy of the access by checking if the user or process has a valid reason or permission to access the sensitive attributes, considering the organization’s access control policies.
* Assess the potential impact of the access attempt on the organization’s security posture, focusing on credential theft or privilege escalation risks.
* Document findings and, if necessary, escalate the incident to the appropriate security team for further action or remediation.

**False positive analysis**

* Access by legitimate administrative accounts: Regular access by system administrators to sensitive LDAP attributes can trigger alerts. To manage this, create exceptions for known administrative accounts by excluding their SIDs from the detection rule.
* Scheduled system processes: Automated tasks or system processes that require access to certain LDAP attributes may cause false positives. Identify these processes and exclude their specific event codes or AccessMasks if they are consistently benign.
* Service accounts: Service accounts that perform routine directory operations might access sensitive attributes as part of their normal function. Exclude these accounts by adding their SIDs to the exception list to prevent unnecessary alerts.
* Monitoring tools: Security or monitoring tools that scan directory attributes for compliance or auditing purposes can generate false positives. Whitelist these tools by excluding their event sources or specific actions from the detection criteria.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Conduct a thorough review of the access logs to identify any unauthorized users or systems that accessed the sensitive LDAP attributes.
* Reset passwords and revoke any potentially compromised credentials associated with the affected accounts, focusing on those with access to sensitive attributes.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine the scope of the breach.
* Implement additional monitoring on the affected systems and accounts to detect any further suspicious activities or attempts to access sensitive LDAP attributes.
* Review and update access controls and permissions for sensitive LDAP attributes to ensure they are restricted to only necessary personnel.
* Conduct a post-incident analysis to identify any gaps in security controls and update policies or procedures to prevent similar incidents in the future.


## Setup [_setup_1511]

**Setup**

The *Audit Directory Service Access* logging policy must be configured for (Success, Failure). Steps to implement the logging policy with Advanced Audit Configuration:

```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Policies Configuration >
Audit Policies >
DS Access >
Audit Directory Service Access (Success,Failure)
```


## Rule query [_rule_query_5674]

```js
any where event.code == "4662" and

  not winlog.event_data.SubjectUserSid : "S-1-5-18" and

  winlog.event_data.Properties : (
   /* unixUserPassword */
  "*612cb747-c0e8-4f92-9221-fdd5f15b550d*",

  /* ms-PKI-AccountCredentials */
  "*b8dfa744-31dc-4ef1-ac7c-84baf7ef9da7*",

  /*  ms-PKI-DPAPIMasterKeys */
  "*b3f93023-9239-4f7c-b99c-6745d87adbc2*",

  /* msPKI-CredentialRoamingTokens */
  "*b7ff5a38-0818-42b0-8110-d3d154c97f24*"
  ) and

  /*
   Excluding noisy AccessMasks
   0x0 undefined and 0x100 Control Access
   https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662
   */
  not winlog.event_data.AccessMask in ("0x0", "0x100")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)

* Technique:

    * Name: Unsecured Credentials
    * ID: T1552
    * Reference URL: [https://attack.mitre.org/techniques/T1552/](https://attack.mitre.org/techniques/T1552/)

* Sub-technique:

    * Name: Private Keys
    * ID: T1552.004
    * Reference URL: [https://attack.mitre.org/techniques/T1552/004/](https://attack.mitre.org/techniques/T1552/004/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Sub-technique:

    * Name: Domain Accounts
    * ID: T1078.002
    * Reference URL: [https://attack.mitre.org/techniques/T1078/002/](https://attack.mitre.org/techniques/T1078/002/)




---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-access-to-ldap-attributes.html
---

# Suspicious Access to LDAP Attributes [prebuilt-rule-8-17-4-suspicious-access-to-ldap-attributes]

Identify read access to a high number of Active Directory object attributes. The knowledge of objects properties can help adversaries find vulnerabilities, elevate privileges or collect sensitive information.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-system.security*
* logs-windows.forwarded*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Discovery
* Data Source: System
* Data Source: Active Directory
* Data Source: Windows
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4827]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Access to LDAP Attributes**

LDAP (Lightweight Directory Access Protocol) is crucial for querying and modifying directory services like Active Directory, which stores user credentials and permissions. Adversaries exploit LDAP to enumerate directory attributes, seeking vulnerabilities or sensitive data. The detection rule identifies unusual read access patterns, such as excessive attribute queries, which may indicate reconnaissance or privilege escalation attempts.

**Possible investigation steps**

* Review the event logs for the specific event code 4662 to gather details about the suspicious read access, focusing on the winlog.event_data.Properties field to understand which attributes were accessed.
* Identify the user associated with the suspicious activity by examining the winlog.event_data.SubjectUserSid field, and determine if this user has a legitimate reason to access a high number of Active Directory object attributes.
* Check the user’s recent activity and login history to identify any unusual patterns or anomalies that could indicate compromised credentials or unauthorized access.
* Investigate the source machine from which the LDAP queries originated to determine if it is a known and trusted device or if it shows signs of compromise or unauthorized use.
* Correlate this event with other security alerts or logs to identify if this activity is part of a larger pattern of reconnaissance or privilege escalation attempts within the network.

**False positive analysis**

* Regular system maintenance or updates may trigger high attribute read access. Exclude known maintenance accounts from the rule to prevent false alerts.
* Automated scripts or applications that query Active Directory for legitimate purposes can cause excessive attribute reads. Identify and whitelist these scripts or applications to reduce noise.
* Security audits or compliance checks often involve extensive directory queries. Coordinate with IT and security teams to recognize these activities and adjust the rule to exclude them.
* Service accounts with legitimate high-volume access patterns should be reviewed and, if deemed non-threatening, added to an exception list to avoid unnecessary alerts.
* Consider the context of the access, such as time of day or associated user activity, to differentiate between normal and suspicious behavior. Adjust the rule to account for these patterns where applicable.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Conduct a thorough review of the user account associated with the suspicious LDAP access to determine if it has been compromised. Reset the account credentials and enforce multi-factor authentication.
* Analyze the event logs to identify any other systems or accounts that may have been accessed using similar methods, and apply the same containment measures.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine the full scope of the breach.
* Implement additional monitoring on LDAP queries and Active Directory access to detect similar patterns of excessive attribute queries in the future.
* Review and tighten access controls and permissions within Active Directory to ensure that only necessary attributes are accessible to users based on their roles.
* Conduct a post-incident review to identify any gaps in security controls and update policies or procedures to prevent recurrence of similar threats.


## Setup [_setup_1541]

The *Audit Directory Service Changes* logging policy must be configured for (Success, Failure). Steps to implement the logging policy with Advanced Audit Configuration:

Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policies Configuration > Audit Policies > DS Access > Audit Directory Service Changes (Success,Failure)


## Rule query [_rule_query_5782]

```js
any where event.code == "4662" and not winlog.event_data.SubjectUserSid : "S-1-5-18" and
 winlog.event_data.AccessMaskDescription == "Read Property" and length(winlog.event_data.Properties) >= 2000
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Permission Groups Discovery
    * ID: T1069
    * Reference URL: [https://attack.mitre.org/techniques/T1069/](https://attack.mitre.org/techniques/T1069/)




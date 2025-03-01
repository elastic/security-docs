---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-active-directory-replication-account-backdoor.html
---

# Potential Active Directory Replication Account Backdoor [prebuilt-rule-8-17-4-potential-active-directory-replication-account-backdoor]

Identifies the modification of the nTSecurityDescriptor attribute in a domain object with rights related to DCSync to a user/computer account. Attackers can use this backdoor to re-obtain access to hashes of any user/computer.

**Rule type**: query

**Rule indices**:

* winlogbeat-*
* logs-system.security*
* logs-windows.forwarded*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://twitter.com/menasec1/status/1111556090137903104](https://twitter.com/menasec1/status/1111556090137903104)
* [https://www.specterops.io/assets/resources/an_ace_up_the_sleeve.pdf](https://www.specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
* [https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_account_backdoor_dcsync_rights.yml](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_account_backdoor_dcsync_rights.yml)
* [https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-all](https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-all)
* [https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes](https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes)
* [https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-in-filtered-set](https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-in-filtered-set)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: Active Directory
* Use Case: Active Directory Monitoring
* Data Source: System
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4709]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Active Directory Replication Account Backdoor**

Active Directory (AD) is a critical component in many enterprise environments, managing user and computer accounts. Adversaries may exploit AD by modifying security descriptors to gain replication rights, allowing them to extract sensitive credential data. The detection rule identifies suspicious changes to security descriptors, specifically targeting attributes that grant replication capabilities, which could indicate an attempt to establish a backdoor for credential access.

**Possible investigation steps**

* Review the event logs for the specific event code 5136 to identify the exact changes made to the nTSecurityDescriptor attribute and the account involved.
* Examine the winlog.event_data.AttributeValue to determine if the changes include the specific GUIDs (*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2, *1131f6aa-9c07-11d1-f79f-00c04fc2dcd2, *89e95b76-444d-4c62-991a-0facbeda640c) that indicate replication rights were granted.
* Identify the user or computer account (S-1-5-21-*) that was granted these rights and assess whether this account should have such permissions.
* Check the account’s recent activity and login history to identify any unusual or unauthorized access patterns.
* Investigate any recent changes or anomalies in the directory service that could correlate with the suspicious modification event.
* Consult with the Active Directory administrators to verify if the changes were authorized and part of any legitimate administrative tasks.

**False positive analysis**

* Changes made by authorized administrators during legitimate security audits or system maintenance can trigger the rule. To manage this, create exceptions for known administrative accounts performing regular audits.
* Automated scripts or tools used for Active Directory management might modify security descriptors as part of their normal operation. Identify these scripts and exclude their associated accounts from triggering alerts.
* Scheduled tasks or system processes that require replication rights for synchronization purposes may also cause false positives. Review and whitelist these processes if they are verified as non-threatening.
* Third-party applications with legitimate replication needs might alter security descriptors. Ensure these applications are documented and their actions are excluded from the rule.
* Temporary changes during system migrations or upgrades can be mistaken for suspicious activity. Monitor these events closely and apply temporary exceptions as needed.

**Response and remediation**

* Immediately isolate the affected user or computer account from the network to prevent further unauthorized access or data exfiltration.
* Revoke any unauthorized permissions or changes made to the nTSecurityDescriptor attribute for the affected account to remove replication rights.
* Conduct a thorough review of recent changes to the AD environment, focusing on accounts with elevated privileges, to identify any other unauthorized modifications.
* Reset passwords for all accounts that may have been compromised, prioritizing those with administrative or sensitive access.
* Implement additional monitoring on the affected account and related systems to detect any further suspicious activity.
* Escalate the incident to the security operations center (SOC) or incident response team for a comprehensive investigation and to determine the full scope of the breach.
* Review and update access control policies and security descriptors in Active Directory to prevent similar unauthorized changes in the future.


## Setup [_setup_1508]

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


## Rule query [_rule_query_5664]

```js
event.code:"5136" and
  winlog.event_data.AttributeLDAPDisplayName:"nTSecurityDescriptor" and
  winlog.event_data.AttributeValue : (
    (
      *1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-* and
      *1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-* and
      *89e95b76-444d-4c62-991a-0facbeda640c;;S-1-5-21-*
    )
  )
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

* Sub-technique:

    * Name: DCSync
    * ID: T1003.006
    * Reference URL: [https://attack.mitre.org/techniques/T1003/006/](https://attack.mitre.org/techniques/T1003/006/)




---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/adminsdholder-backdoor.html
---

# AdminSDHolder Backdoor [adminsdholder-backdoor]

Detects modifications in the AdminSDHolder object. Attackers can abuse the SDProp process to implement a persistent backdoor in Active Directory. SDProp compares the permissions on protected objects with those defined on the AdminSDHolder object. If the permissions on any of the protected accounts and groups do not match, the permissions on the protected accounts and groups are reset to match those of the domain’s AdminSDHolder object, regaining their Administrative Privileges.

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

* [https://adsecurity.org/?p=1906](https://adsecurity.org/?p=1906)
* [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c—​protected-accounts-and-groups-in-active-directory#adminsdholder](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c—​protected-accounts-and-groups-in-active-directory#adminsdholder)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Use Case: Active Directory Monitoring
* Data Source: Active Directory
* Data Source: System
* Resources: Investigation Guide

**Version**: 211

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_123]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AdminSDHolder Backdoor**

The AdminSDHolder object in Active Directory is crucial for maintaining consistent permissions across privileged accounts. It ensures that any changes to these accounts are reverted to match the AdminSDHolder’s settings. Adversaries exploit this by modifying the AdminSDHolder to create persistent backdoors, regaining administrative privileges. The detection rule identifies such abuses by monitoring specific directory service changes, focusing on modifications to the AdminSDHolder object, thus alerting security teams to potential threats.

**Possible investigation steps**

* Review the event logs for entries with event.code:5136 to identify specific changes made to the AdminSDHolder object.
* Examine the winlog.event_data.ObjectDN field to confirm the object path is CN=AdminSDHolder,CN=System* and verify the nature of the modifications.
* Identify the user account responsible for the changes by checking the event logs for the associated user information.
* Investigate the history of the identified user account to determine if there are any other suspicious activities or patterns of behavior.
* Assess the current permissions on the AdminSDHolder object and compare them with the expected baseline to identify unauthorized changes.
* Check for any recent changes in group memberships or permissions of privileged accounts that could indicate exploitation of the AdminSDHolder backdoor.
* Collaborate with the IT or security team to determine if the changes were authorized or if further action is needed to secure the environment.

**False positive analysis**

* Routine administrative changes to the AdminSDHolder object can trigger alerts. To manage this, establish a baseline of expected changes and create exceptions for these known activities.
* Scheduled maintenance or updates to Active Directory may result in temporary modifications to the AdminSDHolder object. Document these events and exclude them from triggering alerts during the maintenance window.
* Automated scripts or tools used for Active Directory management might modify the AdminSDHolder object as part of their normal operation. Identify these tools and whitelist their activities to prevent false positives.
* Changes made by trusted security personnel or systems should be logged and reviewed. Implement a process to verify and exclude these changes from alerting if they are part of approved security operations.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or privilege escalation.
* Revert any unauthorized changes to the AdminSDHolder object by restoring it from a known good backup or manually resetting its permissions to the default secure state.
* Conduct a thorough review of all privileged accounts and groups to ensure their permissions align with organizational security policies and have not been altered to match the compromised AdminSDHolder settings.
* Reset passwords for all accounts that were potentially affected or had their permissions altered, focusing on privileged accounts to prevent adversaries from regaining access.
* Implement additional monitoring on the AdminSDHolder object and other critical Active Directory objects to detect any future unauthorized modifications promptly.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine the scope of the breach, including identifying any other compromised systems or accounts.
* Review and update access control policies and security configurations to prevent similar attacks, ensuring that only authorized personnel have the ability to modify critical Active Directory objects.


## Rule query [_rule_query_129]

```js
event.code:5136 and winlog.event_data.ObjectDN:CN=AdminSDHolder,CN=System*
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Sub-technique:

    * Name: Domain Accounts
    * ID: T1078.002
    * Reference URL: [https://attack.mitre.org/techniques/T1078/002/](https://attack.mitre.org/techniques/T1078/002/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)




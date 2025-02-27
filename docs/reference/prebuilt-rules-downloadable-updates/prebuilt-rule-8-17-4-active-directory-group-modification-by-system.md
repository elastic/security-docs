---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-active-directory-group-modification-by-system.html
---

# Active Directory Group Modification by SYSTEM [prebuilt-rule-8-17-4-active-directory-group-modification-by-system]

Identifies a user being added to an active directory group by the SYSTEM (S-1-5-18) user. This behavior can indicate that the attacker has achieved SYSTEM privileges in a domain controller, which attackers can obtain by exploiting vulnerabilities or abusing default group privileges (e.g., Server Operators), and is attempting to pivot to a domain account.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-system.security*
* logs-windows.forwarded*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Use Case: Active Directory Monitoring
* Data Source: Active Directory
* Data Source: System
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4910]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Active Directory Group Modification by SYSTEM**

Active Directory (AD) is a critical component in Windows environments, managing user and group permissions. SYSTEM, a high-privilege account, can modify AD groups, which attackers exploit to gain unauthorized access. By monitoring specific event logs for SYSTEM-initiated group changes, the detection rule identifies potential privilege escalation, signaling an attacker may have compromised a domain controller.

**Possible investigation steps**

* Review the event log entry with event code 4728 to confirm the SYSTEM account (S-1-5-18) initiated the group modification.
* Identify the specific Active Directory group that was modified and determine if it is a sensitive or high-privilege group.
* Check for any recent changes or anomalies in the domain controller’s security logs that might indicate SYSTEM privilege escalation.
* Investigate the timeline of events leading up to the group modification to identify any suspicious activities or patterns.
* Correlate this event with other security alerts or logs to assess if there is a broader attack pattern or campaign.
* Verify if there are any known vulnerabilities or misconfigurations in the domain controller that could have been exploited to gain SYSTEM privileges.

**False positive analysis**

* Routine administrative tasks performed by automated scripts or scheduled tasks may trigger this rule. Review and document these tasks, then create exceptions for known benign scripts to prevent unnecessary alerts.
* System maintenance activities, such as software updates or system reconfigurations, might involve legitimate group modifications by SYSTEM. Coordinate with IT teams to identify and whitelist these activities.
* Certain security tools or monitoring solutions may perform group modifications as part of their normal operation. Verify these tools' actions and exclude them from triggering alerts if they are confirmed to be safe.
* In environments with custom applications that require SYSTEM-level access for group management, ensure these applications are documented and their actions are excluded from detection to avoid false positives.
* Regularly review and update the list of exceptions to ensure they remain relevant and do not inadvertently allow malicious activities to go undetected.

**Response and remediation**

* Immediately isolate the affected domain controller from the network to prevent further unauthorized access or lateral movement by the attacker.
* Revoke any unauthorized group memberships added by the SYSTEM account to prevent privilege escalation and unauthorized access.
* Conduct a thorough review of recent changes in Active Directory, focusing on group modifications and user account activities, to identify any other potential unauthorized changes.
* Reset passwords for all accounts that were added to groups by the SYSTEM account to mitigate the risk of compromised credentials being used.
* Apply security patches and updates to the domain controller to address any vulnerabilities that may have been exploited to gain SYSTEM privileges.
* Monitor for any further suspicious activities or attempts to modify Active Directory groups, using enhanced logging and alerting mechanisms.
* Escalate the incident to the security operations center (SOC) or incident response team for a comprehensive investigation and to determine the full scope of the breach.


## Rule query [_rule_query_5865]

```js
iam where winlog.api == "wineventlog" and event.code == "4728" and
winlog.event_data.SubjectUserSid : "S-1-5-18" and

/* DOMAIN_USERS and local groups */
not group.id : "S-1-5-21-*-513"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)




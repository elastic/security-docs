---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-creation-or-modification-of-a-new-gpo-scheduled-task-or-service.html
---

# Creation or Modification of a new GPO Scheduled Task or Service [prebuilt-rule-8-17-4-creation-or-modification-of-a-new-gpo-scheduled-task-or-service]

Detects the creation or modification of a new Group Policy based scheduled task or service. These methods are used for legitimate system administration, but can also be abused by an attacker with domain admin permissions to execute a malicious payload remotely on all or a subset of the domain joined machines.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.file-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Tactic: Persistence
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 311

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4959]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Creation or Modification of a new GPO Scheduled Task or Service**

Group Policy Objects (GPOs) are crucial for centralized management in Windows environments, allowing administrators to configure settings across domain-joined machines. Adversaries with domain admin rights can exploit GPOs to create or modify scheduled tasks or services, deploying malicious payloads network-wide. The detection rule identifies such activities by monitoring specific file changes in GPO paths, excluding legitimate system processes, thus highlighting potential abuse for privilege escalation or persistence.

**Possible investigation steps**

* Review the file path and name to confirm if the changes were made to "ScheduledTasks.xml" or "Services.xml" within the specified GPO paths, as these are indicative of potential unauthorized modifications.
* Check the process that initiated the file change, ensuring it is not "C:\\Windows\\System32\\dfsrs.exe", which is excluded as a legitimate system process.
* Investigate the user account associated with the file modification event to determine if it has domain admin rights and assess if the activity aligns with their typical behavior or role.
* Examine recent changes in the GPO settings to identify any new or altered scheduled tasks or services that could be used for malicious purposes.
* Correlate the event with other security logs or alerts from data sources like Elastic Endgame, Sysmon, or Microsoft Defender for Endpoint to identify any related suspicious activities or patterns.
* Assess the impact by identifying which domain-joined machines are affected by the GPO changes and determine if any unauthorized tasks or services have been executed.

**False positive analysis**

* Legitimate administrative changes to GPOs can trigger alerts. Regularly review and document scheduled administrative tasks to differentiate between expected and unexpected changes.
* Automated system management tools may modify GPO scheduled tasks or services as part of routine operations. Identify these tools and create exceptions for their processes to reduce noise.
* Updates or patches from Microsoft or other trusted vendors might alter GPO settings. Monitor update schedules and correlate changes with known update activities to verify legitimacy.
* Internal IT scripts or processes that manage GPOs for configuration consistency can cause false positives. Ensure these scripts are well-documented and consider excluding their specific actions from monitoring.
* Temporary changes made by IT staff for troubleshooting or testing purposes can be mistaken for malicious activity. Implement a change management process to log and approve such activities, allowing for easy exclusion from alerts.

**Response and remediation**

* Immediately isolate affected systems from the network to prevent further spread of any malicious payloads deployed via the modified GPO scheduled tasks or services.
* Revoke domain admin privileges from any accounts that are suspected of being compromised to prevent further unauthorized modifications to GPOs.
* Conduct a thorough review of the modified ScheduledTasks.xml and Services.xml files to identify any unauthorized or malicious entries, and revert them to their previous legitimate state.
* Utilize endpoint detection and response (EDR) tools to scan for and remove any malicious payloads that may have been executed on domain-joined machines as a result of the GPO modifications.
* Notify the security operations center (SOC) and escalate the incident to the incident response team for further investigation and to determine the scope of the compromise.
* Implement additional monitoring on GPO paths and domain admin activities to detect any further unauthorized changes or suspicious behavior.
* Review and strengthen access controls and auditing policies for GPO management to prevent unauthorized modifications in the future.


## Rule query [_rule_query_5914]

```js
file where host.os.type == "windows" and event.type != "deletion" and event.action != "open" and
 file.name : ("ScheduledTasks.xml", "Services.xml") and
  file.path : (
    "?:\\Windows\\SYSVOL\\domain\\Policies\\*\\MACHINE\\Preferences\\ScheduledTasks\\ScheduledTasks.xml",
    "?:\\Windows\\SYSVOL\\domain\\Policies\\*\\MACHINE\\Preferences\\Services\\Services.xml"
  ) and
  not process.executable : "C:\\Windows\\System32\\dfsrs.exe"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Domain or Tenant Policy Modification
    * ID: T1484
    * Reference URL: [https://attack.mitre.org/techniques/T1484/](https://attack.mitre.org/techniques/T1484/)

* Sub-technique:

    * Name: Group Policy Modification
    * ID: T1484.001
    * Reference URL: [https://attack.mitre.org/techniques/T1484/001/](https://attack.mitre.org/techniques/T1484/001/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Scheduled Task/Job
    * ID: T1053
    * Reference URL: [https://attack.mitre.org/techniques/T1053/](https://attack.mitre.org/techniques/T1053/)

* Sub-technique:

    * Name: Scheduled Task
    * ID: T1053.005
    * Reference URL: [https://attack.mitre.org/techniques/T1053/005/](https://attack.mitre.org/techniques/T1053/005/)




---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-hidden-files-and-directories-via-hidden-flag.html
---

# Hidden Files and Directories via Hidden Flag [prebuilt-rule-8-17-4-hidden-files-and-directories-via-hidden-flag]

Identify activity related where adversaries can add the *hidden* flag to files to hide them from the user in an attempt to evade detection.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* auditbeat-*
* logs-auditd_manager.auditd-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* OS: macOS
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Auditd Manager
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4335]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Hidden Files and Directories via Hidden Flag**

In Unix-like systems, the *hidden* flag can be set on files to conceal them from standard directory listings, a feature often exploited by adversaries to obscure malicious files. Attackers may use commands like `chflags` to apply this flag, making detection challenging. The detection rule targets file creation events involving `chflags`, helping identify potential misuse by monitoring for suspicious activity on Linux and macOS systems.

**Possible investigation steps**

* Review the alert details to confirm the host operating system is Linux, as specified by the query field `host.os.type == "linux"`.
* Examine the process execution details to verify that the `chflags` command was used, as indicated by `process.name == "chflags"`.
* Investigate the file creation event to identify the specific file or directory that had the *hidden* flag applied, focusing on the `event.type == "creation"` field.
* Check the user account associated with the `chflags` command execution to determine if it aligns with expected user behavior or if it might indicate unauthorized access.
* Analyze recent system logs and user activity on the affected host to identify any other suspicious behavior or anomalies that could suggest malicious intent.
* Correlate this event with other alerts or indicators of compromise on the same host to assess if this is part of a larger attack pattern or isolated incident.

**False positive analysis**

* System maintenance scripts may use the chflags command to manage file visibility for legitimate purposes. Review scheduled tasks and scripts to identify benign uses and create exceptions for these processes.
* Backup and recovery operations might employ the hidden flag to protect critical files from accidental deletion. Verify backup software configurations and exclude these operations from triggering alerts.
* Development environments could use hidden files to manage version control or configuration settings. Collaborate with development teams to understand their workflows and whitelist known development-related activities.
* Security tools and utilities may use the hidden flag as part of their normal operation to protect sensitive files. Identify these tools and add them to an exception list to prevent unnecessary alerts.
* User customization scripts might apply the hidden flag to personalize the user environment. Engage with users to document these customizations and exclude them from detection rules.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further malicious activity or lateral movement.
* Terminate any suspicious processes associated with `chflags` to halt any ongoing attempts to hide files.
* Conduct a thorough review of recently created files and directories on the affected system to identify and assess any hidden files for malicious content.
* Restore any critical files that may have been hidden or altered from known good backups to ensure system integrity.
* Implement file integrity monitoring to detect unauthorized changes to file attributes, including the hidden flag, on critical systems.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.
* Update and enhance endpoint detection and response (EDR) solutions to improve detection capabilities for similar threats in the future.


## Rule query [_rule_query_5327]

```js
file where host.os.type == "linux" and event.type == "creation" and process.name == "chflags"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Hide Artifacts
    * ID: T1564
    * Reference URL: [https://attack.mitre.org/techniques/T1564/](https://attack.mitre.org/techniques/T1564/)

* Sub-technique:

    * Name: Hidden Files and Directories
    * ID: T1564.001
    * Reference URL: [https://attack.mitre.org/techniques/T1564/001/](https://attack.mitre.org/techniques/T1564/001/)




---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-sensitive-files-compression-inside-a-container.html
---

# Sensitive Files Compression Inside A Container [prebuilt-rule-8-17-4-sensitive-files-compression-inside-a-container]

Identifies the use of a compression utility to collect known files containing sensitive information, such as credentials and system configurations inside a container.

**Rule type**: eql

**Rule indices**:

* logs-cloud_defend*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-6m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Data Source: Elastic Defend for Containers
* Domain: Container
* OS: Linux
* Use Case: Threat Detection
* Tactic: Collection
* Tactic: Credential Access
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4119]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Sensitive Files Compression Inside A Container**

Containers are lightweight, portable environments used to run applications consistently across different systems. Adversaries may exploit compression utilities within containers to gather and exfiltrate sensitive files, such as credentials and configuration files. The detection rule identifies suspicious compression activities by monitoring for specific utilities and file paths, flagging potential unauthorized data collection attempts.

**Possible investigation steps**

* Review the process details to confirm the use of compression utilities such as zip, tar, gzip, hdiutil, or 7z within the container environment, focusing on the process.name and process.args fields.
* Examine the specific file paths listed in the process.args to determine if they include sensitive files like SSH keys, AWS credentials, or Docker configurations, which could indicate unauthorized data collection.
* Identify the container.id associated with the alert to gather more context about the container’s purpose, owner, and any recent changes or deployments that might explain the activity.
* Check the event.type field for "start" to verify the timing of the process initiation and correlate it with any known legitimate activities or scheduled tasks within the container.
* Investigate the user or service account under which the process was executed to assess whether it has the necessary permissions and if the activity aligns with expected behavior for that account.
* Look for any related alerts or logs that might indicate a broader pattern of suspicious activity within the same container or across other containers in the environment.

**False positive analysis**

* Routine backup operations may trigger the rule if they involve compressing sensitive files for storage. To handle this, identify and exclude backup processes or scripts that are known and trusted.
* Automated configuration management tools might compress configuration files as part of their normal operation. Exclude these tools by specifying their process names or paths in the exception list.
* Developers or system administrators might compress sensitive files during legitimate troubleshooting or maintenance activities. Establish a process to log and review these activities, and exclude them if they are verified as non-threatening.
* Continuous integration and deployment pipelines could involve compressing configuration files for deployment purposes. Identify these pipelines and exclude their associated processes to prevent false positives.
* Security tools that perform regular audits or scans might compress files for analysis. Ensure these tools are recognized and excluded from triggering the rule.

**Response and remediation**

* Immediately isolate the affected container to prevent further data exfiltration or unauthorized access. This can be done by stopping the container or disconnecting it from the network.
* Conduct a thorough review of the compressed files and their contents to assess the extent of sensitive data exposure. Focus on the specific file paths identified in the alert.
* Change credentials and keys that may have been compromised, including SSH keys, AWS credentials, and Docker configurations. Ensure that new credentials are distributed securely.
* Review and update access controls and permissions for sensitive files within containers to minimize exposure. Ensure that only necessary processes and users have access to these files.
* Implement monitoring and alerting for similar compression activities in other containers to detect potential threats early. Use the identified process names and arguments as indicators.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems or data have been affected.
* Conduct a post-incident review to identify gaps in security controls and update container security policies to prevent recurrence.


## Rule query [_rule_query_5136]

```js
process where container.id: "*" and event.type== "start" and

/*account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg*/
(process.name: ("zip", "tar", "gzip", "hdiutil", "7z") or process.args: ("zip", "tar", "gzip", "hdiutil", "7z"))
and process.args: (
"/root/.ssh/id_rsa",
"/root/.ssh/id_rsa.pub",
"/root/.ssh/id_ed25519",
"/root/.ssh/id_ed25519.pub",
"/root/.ssh/authorized_keys",
"/root/.ssh/authorized_keys2",
"/root/.ssh/known_hosts",
"/root/.bash_history",
"/etc/hosts",
"/home/*/.ssh/id_rsa",
"/home/*/.ssh/id_rsa.pub",
"/home/*/.ssh/id_ed25519",
"/home/*/.ssh/id_ed25519.pub",
"/home/*/.ssh/authorized_keys",
"/home/*/.ssh/authorized_keys2",
"/home/*/.ssh/known_hosts",
"/home/*/.bash_history",
"/root/.aws/credentials",
"/root/.aws/config",
"/home/*/.aws/credentials",
"/home/*/.aws/config",
"/root/.docker/config.json",
"/home/*/.docker/config.json",
"/etc/group",
"/etc/passwd",
"/etc/shadow",
"/etc/gshadow")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Unsecured Credentials
    * ID: T1552
    * Reference URL: [https://attack.mitre.org/techniques/T1552/](https://attack.mitre.org/techniques/T1552/)

* Sub-technique:

    * Name: Credentials In Files
    * ID: T1552.001
    * Reference URL: [https://attack.mitre.org/techniques/T1552/001/](https://attack.mitre.org/techniques/T1552/001/)

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Archive Collected Data
    * ID: T1560
    * Reference URL: [https://attack.mitre.org/techniques/T1560/](https://attack.mitre.org/techniques/T1560/)

* Sub-technique:

    * Name: Archive via Utility
    * ID: T1560.001
    * Reference URL: [https://attack.mitre.org/techniques/T1560/001/](https://attack.mitre.org/techniques/T1560/001/)




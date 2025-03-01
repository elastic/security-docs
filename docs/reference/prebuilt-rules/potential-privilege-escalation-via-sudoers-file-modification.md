---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-privilege-escalation-via-sudoers-file-modification.html
---

# Potential Privilege Escalation via Sudoers File Modification [potential-privilege-escalation-via-sudoers-file-modification]

A sudoers file specifies the commands users or groups can run and from which terminals. Adversaries can take advantage of these configurations to execute commands as other users or spawn processes with higher privileges.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/security-labs/primer-on-persistence-mechanisms](https://www.elastic.co/security-labs/primer-on-persistence-mechanisms)

**Tags**:

* Domain: Endpoint
* OS: Linux
* OS: macOS
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_743]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Privilege Escalation via Sudoers File Modification**

The sudoers file is crucial in Unix-like systems, defining user permissions for executing commands with elevated privileges. Adversaries may exploit this by modifying the file to allow unauthorized privilege escalation, often using the NOPASSWD directive to bypass password prompts. The detection rule identifies suspicious process activities, such as attempts to alter sudoers configurations, by monitoring specific command patterns indicative of such exploits.

**Possible investigation steps**

* Review the alert details to identify the specific process that triggered the alert, focusing on the process.args field to confirm the presence of the **NOPASSWD*ALL** pattern.
* Examine the process execution context, including the user account under which the process was initiated, to determine if it aligns with expected behavior or if it indicates potential misuse.
* Check the system’s sudoers file for recent modifications, especially looking for unauthorized entries or changes that include the NOPASSWD directive.
* Investigate the command history of the user associated with the alert to identify any suspicious activities or commands executed around the time of the alert.
* Correlate the event with other logs or alerts from the same host or user to identify any patterns or additional indicators of compromise that might suggest a broader attack.

**False positive analysis**

* Routine administrative tasks may trigger the rule if administrators frequently update the sudoers file to add legitimate NOPASSWD entries for automation purposes. To manage this, create exceptions for known administrative scripts or processes that are regularly reviewed and approved.
* Configuration management tools like Ansible or Puppet might modify the sudoers file as part of their normal operation. Exclude these tools from triggering alerts by identifying their specific process names or paths and adding them to an exception list.
* Development environments where developers are granted temporary elevated privileges for testing purposes can cause false positives. Implement a policy to log and review these changes separately, ensuring they are reverted after use.
* Automated scripts that require passwordless sudo access for operational efficiency might be flagged. Document these scripts and their usage, and configure the detection system to ignore these specific, well-documented cases.
* System updates or patches that modify sudoers configurations as part of their installation process can be mistaken for malicious activity. Monitor update schedules and correlate them with alerts to identify and exclude these benign changes.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or privilege escalation.
* Review and revert any unauthorized changes to the sudoers file by restoring it from a known good backup or manually correcting the entries to remove any NOPASSWD directives added by the adversary.
* Conduct a thorough audit of user accounts and permissions on the affected system to identify and remove any unauthorized accounts or privilege assignments.
* Reset passwords for all accounts with elevated privileges on the affected system to ensure that compromised credentials cannot be reused.
* Deploy endpoint detection and response (EDR) tools to monitor for any further suspicious activities or attempts to modify the sudoers file across the network.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if the threat has spread to other systems.
* Implement additional logging and alerting for changes to the sudoers file and other critical configuration files to enhance detection of similar threats in the future.


## Rule query [_rule_query_790]

```js
event.category:process and event.type:start and process.args:(echo and *NOPASSWD*ALL*)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Sub-technique:

    * Name: Sudo and Sudo Caching
    * ID: T1548.003
    * Reference URL: [https://attack.mitre.org/techniques/T1548/003/](https://attack.mitre.org/techniques/T1548/003/)




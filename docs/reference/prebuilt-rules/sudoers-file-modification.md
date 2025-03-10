---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/sudoers-file-modification.html
---

# Sudoers File Modification [sudoers-file-modification]

A sudoers file specifies the commands that users or groups can run and from which terminals. Adversaries can take advantage of these configurations to execute commands as other users or spawn processes with higher privileges.

**Rule type**: new_terms

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

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

**Version**: 206

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_959]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Sudoers File Modification**

The sudoers file is crucial in Unix-like systems, defining user permissions for executing commands with elevated privileges. Adversaries may exploit this by altering the file to gain unauthorized access or escalate privileges. The detection rule identifies suspicious changes to the sudoers file, excluding legitimate processes, to flag potential privilege escalation attempts.

**Possible investigation steps**

* Review the alert details to identify the specific file path that triggered the alert, focusing on /etc/sudoers* or /private/etc/sudoers*.
* Examine the process information associated with the change event, particularly the process.name and process.executable fields, to determine if the modification was made by a suspicious or unauthorized process.
* Check the user account associated with the process that made the change to the sudoers file to assess if the account has a legitimate reason to modify the file.
* Investigate recent login activity and user behavior for the account involved in the modification to identify any anomalies or signs of compromise.
* Review system logs around the time of the alert to gather additional context on what other activities occurred on the system, which might indicate a broader attack or compromise.
* Assess the current state of the sudoers file to identify any unauthorized or suspicious entries that could indicate privilege escalation attempts.

**False positive analysis**

* System updates and package installations can trigger changes to the sudoers file. Exclude processes like dpkg, yum, dnf, and platform-python from triggering alerts as they are commonly involved in legitimate updates.
* Configuration management tools such as Puppet and Chef may modify the sudoers file as part of their normal operations. Exclude process executables like /opt/chef/embedded/bin/ruby and /opt/puppetlabs/puppet/bin/ruby to prevent false positives.
* Docker daemon processes might interact with the sudoers file during container operations. Exclude /usr/bin/dockerd to avoid unnecessary alerts related to Docker activities.
* Regularly review and update the exclusion list to ensure it reflects the current environment and operational tools, minimizing false positives while maintaining security vigilance.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or privilege escalation.
* Review the recent changes to the sudoers file to identify unauthorized modifications and revert them to the last known good configuration.
* Conduct a thorough examination of system logs to identify any unauthorized access or actions performed using elevated privileges, focusing on the time frame of the detected change.
* Reset passwords and review access permissions for all users with sudo privileges to ensure no unauthorized accounts have been added or existing accounts have been compromised.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems have been affected.
* Implement additional monitoring on the affected system and similar systems to detect any further attempts to modify the sudoers file or other privilege escalation activities.
* Review and update security policies and configurations to prevent similar incidents, ensuring that only authorized processes can modify the sudoers file.


## Rule query [_rule_query_1007]

```js
event.category:file and event.type:change and file.path:(/etc/sudoers* or /private/etc/sudoers*) and
not process.name:(dpkg or platform-python or puppet or yum or dnf) and
not process.executable:(/opt/chef/embedded/bin/ruby or /opt/puppetlabs/puppet/bin/ruby or /usr/bin/dockerd)
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




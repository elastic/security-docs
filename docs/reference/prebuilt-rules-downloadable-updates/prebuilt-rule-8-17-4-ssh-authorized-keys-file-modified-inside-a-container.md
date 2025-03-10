---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-ssh-authorized-keys-file-modified-inside-a-container.html
---

# SSH Authorized Keys File Modified Inside a Container [prebuilt-rule-8-17-4-ssh-authorized-keys-file-modified-inside-a-container]

This rule detects the creation or modification of an authorized_keys or sshd_config file inside a container. The Secure Shell (SSH) authorized_keys file specifies which users are allowed to log into a server using public key authentication. Adversaries may modify it to maintain persistence on a victim host by adding their own public key(s). Unexpected and unauthorized SSH usage inside a container can be an indicator of compromise and should be investigated.

**Rule type**: eql

**Rule indices**:

* logs-cloud_defend*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-6m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Data Source: Elastic Defend for Containers
* Domain: Container
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Lateral Movement
* Resources: Investigation Guide

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4130]

**Triage and analysis**

[TBC: QUOTE]
**Investigating SSH Authorized Keys File Modified Inside a Container**

In containerized environments, SSH keys facilitate secure access, but adversaries can exploit this by altering the authorized_keys file to gain unauthorized access. This detection rule identifies suspicious changes to SSH configuration files within containers, signaling potential persistence tactics. By monitoring file modifications, it helps detect unauthorized SSH usage, a common indicator of compromise.

**Possible investigation steps**

* Review the container ID associated with the alert to identify the specific container where the modification occurred.
* Examine the timestamp of the event to determine when the file change or creation took place and correlate it with any known activities or changes in the environment.
* Investigate the user account or process that made the modification to the authorized_keys or sshd_config file to assess if it was an authorized action.
* Check for any recent SSH connections to the container, especially those using public key authentication, to identify potential unauthorized access.
* Analyze the contents of the modified authorized_keys or sshd_config file to identify any suspicious or unauthorized keys or configurations.
* Review the container’s logs and any related network activity around the time of the modification for signs of compromise or lateral movement attempts.

**False positive analysis**

* Routine updates or deployments within containers may modify SSH configuration files, leading to false positives. To manage this, create exceptions for known update processes or deployment scripts that regularly alter these files.
* Automated configuration management tools like Ansible or Puppet might change SSH files as part of their normal operation. Identify these tools and exclude their activities from triggering alerts by specifying their process IDs or user accounts.
* Development or testing environments often see frequent changes to SSH keys for legitimate reasons. Consider excluding these environments from the rule or setting up a separate, less sensitive monitoring profile for them.
* Scheduled maintenance tasks that involve SSH key rotation can trigger alerts. Document these tasks and schedule exceptions during their execution windows to prevent unnecessary alerts.
* Container orchestration systems might modify SSH configurations as part of scaling or updating services. Recognize these patterns and adjust the rule to ignore changes made by these systems.

**Response and remediation**

* Immediately isolate the affected container to prevent further unauthorized access or lateral movement within the environment.
* Revoke any unauthorized SSH keys found in the authorized_keys file to cut off the adversary’s access.
* Conduct a thorough review of all SSH configuration files within the container to ensure no additional unauthorized modifications have been made.
* Restore the container from a known good backup if available, ensuring that the backup does not contain the unauthorized changes.
* Implement stricter access controls and monitoring on SSH usage within containers to prevent similar incidents in the future.
* Escalate the incident to the security operations team for further investigation and to determine if other containers or systems have been compromised.
* Update detection and alerting mechanisms to include additional indicators of compromise related to SSH key manipulation and unauthorized access attempts.


## Rule query [_rule_query_5147]

```js
file where container.id:"*" and
  event.type in ("change", "creation") and file.name: ("authorized_keys", "authorized_keys2", "sshd_config")
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

* Sub-technique:

    * Name: SSH Authorized Keys
    * ID: T1098.004
    * Reference URL: [https://attack.mitre.org/techniques/T1098/004/](https://attack.mitre.org/techniques/T1098/004/)

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)

* Sub-technique:

    * Name: SSH
    * ID: T1021.004
    * Reference URL: [https://attack.mitre.org/techniques/T1021/004/](https://attack.mitre.org/techniques/T1021/004/)

* Technique:

    * Name: Remote Service Session Hijacking
    * ID: T1563
    * Reference URL: [https://attack.mitre.org/techniques/T1563/](https://attack.mitre.org/techniques/T1563/)

* Sub-technique:

    * Name: SSH Hijacking
    * ID: T1563.001
    * Reference URL: [https://attack.mitre.org/techniques/T1563/001/](https://attack.mitre.org/techniques/T1563/001/)




---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-unusual-sshd-child-process.html
---

# Unusual SSHD Child Process [prebuilt-rule-8-17-4-unusual-sshd-child-process]

This rule detects the creation of an unusual SSHD child process through the usage of the `new_terms` rule type. Attackers may abuse SSH to maintain persistence on a compromised system, or to establish a backdoor for remote access, potentially resulting in an unusual SSHD child process being created.

**Rule type**: new_terms

**Rule indices**:

* logs-endpoint.events.process*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://hadess.io/the-art-of-linux-persistence/](https://hadess.io/the-art-of-linux-persistence/)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4508]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual SSHD Child Process**

Secure Shell (SSH) is a protocol used to securely access remote systems. Adversaries may exploit SSH to maintain persistence or create backdoors by spawning unexpected child processes. The detection rule identifies anomalies by monitoring process creation events where SSH or SSHD is the parent, focusing on atypical command-line arguments, which may indicate malicious activity.

**Possible investigation steps**

* Review the process command line arguments for the unusual SSHD child process to identify any suspicious or unexpected commands that could indicate malicious activity.
* Check the user account associated with the SSHD child process to determine if it is a legitimate user or if there are signs of compromise, such as unusual login times or locations.
* Investigate the parent process (SSH or SSHD) to understand the context of the connection, including the source IP address and any associated user activity, to assess if it aligns with expected behavior.
* Examine the process tree to identify any subsequent processes spawned by the unusual SSHD child process, which may provide further insight into the attacker’s actions or objectives.
* Correlate the event with other security logs and alerts from the same host or network segment to identify any related suspicious activities or patterns that could indicate a broader attack campaign.

**False positive analysis**

* Legitimate administrative scripts or automation tools may trigger this rule if they execute commands with SSH or SSHD as the parent process. To handle this, identify and document these scripts, then create exceptions for their specific command-line patterns.
* System maintenance tasks or updates that involve SSH connections might appear as unusual child processes. Regularly review and whitelist these known maintenance activities to prevent unnecessary alerts.
* Custom user environments or shell configurations that deviate from standard shells like bash, zsh, or sh could be flagged. Analyze these configurations and exclude them if they are verified as non-threatening.
* Monitoring tools or security solutions that interact with SSH sessions for logging or auditing purposes might generate alerts. Verify these tools' behavior and exclude their processes if they are part of legitimate monitoring activities.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Terminate any suspicious SSHD child processes identified by the alert to halt potential malicious activities.
* Conduct a thorough review of SSH configuration files and access logs to identify unauthorized changes or access patterns, and revert any unauthorized modifications.
* Change all SSH keys and credentials associated with the compromised system to prevent further unauthorized access.
* Implement additional monitoring on the affected system and related network segments to detect any further suspicious activities or attempts to re-establish persistence.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if other systems may be affected.
* Review and update firewall rules and access controls to restrict SSH access to only trusted IP addresses and users, reducing the attack surface for future incidents.


## Rule query [_rule_query_5500]

```js
event.category:process and host.os.type:linux and event.type:start and event.action:exec and
process.parent.name:(ssh or sshd) and process.args_count:2 and
not (
  process.command_line:(-bash or -zsh or -sh) or
  process.name:(ractrans or exectask or tty or tput or ferny-askpass or id or ip)
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)

* Sub-technique:

    * Name: Unix Shell Configuration Modification
    * ID: T1546.004
    * Reference URL: [https://attack.mitre.org/techniques/T1546/004/](https://attack.mitre.org/techniques/T1546/004/)

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

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)




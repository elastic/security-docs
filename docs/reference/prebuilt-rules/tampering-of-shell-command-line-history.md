---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/tampering-of-shell-command-line-history.html
---

# Tampering of Shell Command-Line History [tampering-of-shell-command-line-history]

Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* auditbeat-*
* logs-auditd_manager.auditd-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/security-labs/detecting-log4j2-with-elastic-security](https://www.elastic.co/security-labs/detecting-log4j2-with-elastic-security)

**Tags**:

* Domain: Endpoint
* OS: Linux
* OS: macOS
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Auditd Manager
* Resources: Investigation Guide

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1073]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Tampering of Shell Command-Line History**

Shell command-line history is a crucial feature in Unix-like systems, recording user commands for convenience and auditing. Adversaries may manipulate this history to hide their tracks, using commands to delete or redirect history files, clear history buffers, or disable history logging. The detection rule identifies such tampering by monitoring for suspicious command patterns and arguments indicative of history manipulation attempts.

**Possible investigation steps**

* Review the process execution details to identify the user account associated with the suspicious command, focusing on the process.args field to determine the specific command and arguments used.
* Check the process execution timeline to correlate the suspicious activity with other events on the system, such as logins or file modifications, to understand the context of the tampering attempt.
* Investigate the command history files (.bash_history, .zsh_history) for the affected user accounts to assess the extent of tampering and identify any commands that may have been executed prior to the history manipulation.
* Examine system logs and audit records for any additional indicators of compromise or related suspicious activities, such as unauthorized access attempts or privilege escalation events.
* Verify the current configuration of the HISTFILE and HISTFILESIZE environment variables for the affected user accounts to ensure they have not been altered to disable history logging.

**False positive analysis**

* System administrators or automated scripts may clear command-line history as part of routine maintenance or privacy measures. To handle this, identify and whitelist known scripts or user accounts that perform these actions regularly.
* Developers or power users might redirect or unset history files to manage disk space or for personal preference. Consider excluding specific user accounts or directories from monitoring if these actions are verified as non-malicious.
* Security tools or compliance scripts may execute commands that resemble history tampering to ensure systems are in a desired state. Review and exclude these tools from triggering alerts by adding them to an exception list.
* Temporary testing environments or sandboxed systems might frequently clear history as part of their reset processes. Exclude these environments from the rule to prevent unnecessary alerts.
* Users with privacy concerns might intentionally disable history logging. Engage with these users to understand their needs and adjust monitoring policies accordingly, possibly by excluding their sessions from the rule.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further tampering or data exfiltration.
* Conduct a thorough review of the affected user’s recent command history and system logs to identify any unauthorized or suspicious activities that may have occurred prior to the tampering.
* Restore the tampered history files from a secure backup, if available, to aid in further forensic analysis and ensure continuity of auditing.
* Re-enable and secure shell history logging by resetting the HISTFILE and HISTFILESIZE environment variables to their default values and ensuring they are not set to null or zero.
* Implement stricter access controls and monitoring on the affected system to prevent unauthorized users from modifying shell history files in the future.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems may have been compromised.
* Review and update endpoint detection and response (EDR) configurations to enhance monitoring for similar tampering attempts, ensuring alerts are generated for any future suspicious command patterns.


## Setup [_setup_679]

**Setup**

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_1128]

```js
process where event.action in ("exec", "exec_event", "executed", "process_started") and event.type == "start" and
 (
  ((process.args : ("rm", "echo") or
    (process.args : "ln" and process.args : "-sf" and process.args : "/dev/null") or
    (process.args : "truncate" and process.args : "-s0"))
    and process.args : (".bash_history", "/root/.bash_history", "/home/*/.bash_history","/Users/.bash_history", "/Users/*/.bash_history",
                        ".zsh_history", "/root/.zsh_history", "/home/*/.zsh_history", "/Users/.zsh_history", "/Users/*/.zsh_history")) or
  (process.args : "history" and process.args : "-c") or
  (process.args : "export" and process.args : ("HISTFILE=/dev/null", "HISTFILESIZE=0")) or
  (process.args : "unset" and process.args : "HISTFILE") or
  (process.args : "set" and process.args : "history" and process.args : "+o")
 )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Indicator Removal
    * ID: T1070
    * Reference URL: [https://attack.mitre.org/techniques/T1070/](https://attack.mitre.org/techniques/T1070/)

* Sub-technique:

    * Name: Clear Command History
    * ID: T1070.003
    * Reference URL: [https://attack.mitre.org/techniques/T1070/003/](https://attack.mitre.org/techniques/T1070/003/)




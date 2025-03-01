---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/access-control-list-modification-via-setfacl.html
---

# Access Control List Modification via setfacl [access-control-list-modification-via-setfacl]

This rule detects Linux Access Control List (ACL) modification via the setfacl command.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* auditbeat-*
* logs-auditd_manager.auditd-*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.uptycs.com/blog/threat-research-report-team/evasive-techniques-used-by-malicious-linux-shell-scripts](https://www.uptycs.com/blog/threat-research-report-team/evasive-techniques-used-by-malicious-linux-shell-scripts)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Auditd Manager
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_113]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Access Control List Modification via setfacl**

Access Control Lists (ACLs) in Linux enhance file permission management by allowing more granular access control. The `setfacl` command modifies these ACLs, potentially altering who can access or modify files. Adversaries may exploit `setfacl` to stealthily change permissions, evading detection and maintaining persistence. The detection rule identifies suspicious `setfacl` executions, excluding benign patterns, to flag potential misuse.

**Possible investigation steps**

* Review the process details to confirm the execution of the setfacl command, focusing on the process.name and event.type fields to ensure the alert is valid.
* Examine the process.command_line to understand the specific ACL modifications attempted and identify any unusual or unauthorized changes.
* Investigate the user account associated with the process execution to determine if the action aligns with their typical behavior or role.
* Check the process’s parent process to identify how the setfacl command was initiated and assess if it was part of a legitimate workflow or a potential compromise.
* Correlate the event with other security logs or alerts from the same host to identify any related suspicious activities or patterns that might indicate a broader attack.

**False positive analysis**

* Routine system maintenance tasks may trigger the rule if they involve legitimate use of setfacl. To manage this, identify and document regular maintenance scripts or processes that use setfacl and create exceptions for these specific command lines.
* Backup operations that restore ACLs using setfacl can be mistaken for suspicious activity. Exclude these by adding exceptions for command lines that match known backup procedures, such as those using the --restore option.
* Automated log management tools might use setfacl to manage permissions on log directories like /var/log/journal/. To prevent false positives, exclude these specific directory paths from triggering the rule.
* Custom applications or services that require dynamic permission changes using setfacl could be flagged. Review these applications and, if deemed safe, add their specific command patterns to the exception list to avoid unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or changes.
* Review the process execution logs to identify any unauthorized users or processes that executed the `setfacl` command.
* Revert any unauthorized ACL changes by restoring the original file permissions from a known good backup or configuration.
* Conduct a thorough scan of the system for any additional signs of compromise, such as unauthorized user accounts or unexpected processes.
* Update and patch the system to address any vulnerabilities that may have been exploited to gain access.
* Implement stricter access controls and monitoring on critical systems to detect and prevent unauthorized ACL modifications in the future.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.


## Rule query [_rule_query_117]

```js
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
process.name == "setfacl" and not (
  process.command_line == "/bin/setfacl --restore=-" or
  process.args == "/var/log/journal/" or
  process.parent.name in ("stats.pl", "perl", "find") or
  process.parent.command_line like~ "/bin/sh -c *ansible*"
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: File and Directory Permissions Modification
    * ID: T1222
    * Reference URL: [https://attack.mitre.org/techniques/T1222/](https://attack.mitre.org/techniques/T1222/)

* Sub-technique:

    * Name: Linux and Mac File and Directory Permissions Modification
    * ID: T1222.002
    * Reference URL: [https://attack.mitre.org/techniques/T1222/002/](https://attack.mitre.org/techniques/T1222/002/)




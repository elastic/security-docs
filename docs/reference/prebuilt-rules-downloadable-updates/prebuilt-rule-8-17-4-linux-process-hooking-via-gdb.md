---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-linux-process-hooking-via-gdb.html
---

# Linux Process Hooking via GDB [prebuilt-rule-8-17-4-linux-process-hooking-via-gdb]

This rule monitors for potential memory dumping through gdb. Attackers may leverage memory dumping techniques to attempt secret extraction from privileged processes. Tools that display this behavior include "truffleproc" and "bash-memory-dump". This behavior should not happen by default, and should be investigated thoroughly.

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

* [https://github.com/controlplaneio/truffleproc](https://github.com/controlplaneio/truffleproc)
* [https://github.com/hajzer/bash-memory-dump](https://github.com/hajzer/bash-memory-dump)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Auditd Manager
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4317]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Linux Process Hooking via GDB**

GDB, the GNU Debugger, is a powerful tool used for debugging applications by inspecting their memory and execution flow. Adversaries can exploit GDB to attach to running processes, potentially extracting sensitive information like credentials. The detection rule identifies suspicious use of GDB by monitoring process initiation with specific arguments, flagging potential unauthorized memory access attempts for further investigation.

**Possible investigation steps**

* Review the process details to confirm the presence of GDB by checking if the process name is "gdb" and the arguments include "--pid" or "-p".
* Identify the target process that GDB is attempting to attach to by examining the process arguments and cross-referencing the process ID.
* Investigate the user account under which the GDB process is running to determine if it is authorized to perform debugging tasks on the target process.
* Check the system logs and audit logs for any unusual activity or prior attempts to access sensitive processes or data around the time the GDB process was initiated.
* Correlate the event with other security alerts or anomalies in the environment to assess if this is part of a broader attack pattern or isolated incident.
* Evaluate the necessity and legitimacy of the GDB usage in the context of the system’s normal operations and the user’s role.
* If unauthorized access is suspected, consider isolating the affected system and conducting a deeper forensic analysis to prevent potential data exfiltration.

**False positive analysis**

* Development and debugging activities may trigger the rule when developers use GDB for legitimate purposes. To manage this, create exceptions for specific user accounts or development environments where GDB usage is expected.
* Automated scripts or maintenance tasks that utilize GDB for process inspection can also cause false positives. Identify these scripts and exclude their execution paths or associated user accounts from the rule.
* Security tools or monitoring solutions that use GDB for legitimate process analysis might be flagged. Verify these tools and whitelist their processes or execution contexts to prevent unnecessary alerts.
* Training or educational environments where GDB is used for learning purposes can lead to false positives. Consider excluding these environments or specific user groups from the rule to avoid interference with educational activities.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Terminate the GDB process if it is confirmed to be unauthorized, using process management tools to stop the process safely.
* Conduct a memory dump analysis of the affected system to identify any potential data leakage or extraction of sensitive information.
* Review system logs and audit trails to identify any additional unauthorized access attempts or related suspicious activities.
* Change credentials for any accounts that may have been exposed or accessed during the incident to prevent unauthorized use.
* Implement stricter access controls and monitoring for systems that handle sensitive information to prevent similar incidents.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Rule query [_rule_query_5309]

```js
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started")
 and process.name == "gdb" and process.args in ("--pid", "-p") and
/* Covered by d4ff2f53-c802-4d2e-9fb9-9ecc08356c3f */
process.args != "1"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)

* Sub-technique:

    * Name: Proc Filesystem
    * ID: T1003.007
    * Reference URL: [https://attack.mitre.org/techniques/T1003/007/](https://attack.mitre.org/techniques/T1003/007/)




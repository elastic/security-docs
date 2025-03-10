---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-execution-via-xzbackdoor.html
---

# Potential Execution via XZBackdoor [potential-execution-via-xzbackdoor]

It identifies potential malicious shell executions through remote SSH and detects cases where the sshd service suddenly terminates soon after successful execution, suggesting suspicious behavior similar to the XZ backdoor.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/amlweems/xzbot](https://github.com/amlweems/xzbot)
* [https://access.redhat.com/security/cve/CVE-2024-3094](https://access.redhat.com/security/cve/CVE-2024-3094)
* [https://www.elastic.co/security-labs/500ms-to-midnight](https://www.elastic.co/security-labs/500ms-to-midnight)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Credential Access
* Tactic: Persistence
* Tactic: Lateral Movement
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_681]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Execution via XZBackdoor**

The XZBackdoor leverages SSH, a secure protocol for remote access, to execute malicious commands stealthily. Adversaries exploit SSH by initiating sessions that mimic legitimate activity, then abruptly terminate them post-execution to evade detection. The detection rule identifies anomalies by tracking SSH processes that start and end unexpectedly, especially when non-standard executables are invoked, signaling potential backdoor activity.

**Possible investigation steps**

* Review the SSH session logs on the affected host to identify any unusual or unauthorized access attempts, focusing on sessions that match the process.pid and process.entity_id from the alert.
* Examine the command history and executed commands for the user associated with the user.id in the alert to identify any suspicious or unexpected activities.
* Investigate the non-standard executables invoked by the SSH session by checking the process.executable field to determine if they are legitimate or potentially malicious.
* Analyze the network activity associated with the SSH session, particularly any disconnect_received events, to identify any unusual patterns or connections to suspicious IP addresses.
* Check the exit codes of the SSH processes, especially those with a non-zero process.exit_code, to understand the reason for the abrupt termination and whether it aligns with typical error codes or indicates malicious activity.

**False positive analysis**

* Legitimate administrative SSH sessions may trigger the rule if they involve non-standard executables. To manage this, create exceptions for known administrative scripts or tools that are frequently used in your environment.
* Automated processes or scripts that use SSH for routine tasks might mimic the behavior of the XZBackdoor. Identify these processes and exclude them by specifying their executable paths or command-line patterns in the rule exceptions.
* Security tools or monitoring solutions that perform SSH-based checks could be mistaken for malicious activity. Review these tools and add their signatures to the exclusion list to prevent false alerts.
* Custom applications that use SSH for communication might be flagged. Document these applications and adjust the rule to recognize their specific execution patterns as non-threatening.
* Temporary network issues causing abrupt SSH session terminations could be misinterpreted as suspicious behavior. Monitor network stability and consider excluding known transient disconnections from triggering alerts.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further unauthorized access or lateral movement.
* Terminate any suspicious SSH sessions identified by the detection rule to stop ongoing malicious activity.
* Conduct a thorough review of the affected host’s SSH configuration and logs to identify unauthorized changes or access patterns.
* Reset credentials for any user accounts involved in the suspicious SSH activity to prevent further unauthorized access.
* Restore the affected system from a known good backup if any unauthorized changes or malware are detected.
* Implement network segmentation to limit SSH access to critical systems and reduce the attack surface.
* Escalate the incident to the security operations center (SOC) for further investigation and to determine if additional systems are compromised.


## Rule query [_rule_query_721]

```js
sequence by host.id, user.id with maxspan=1s
 [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.name == "sshd" and
    process.args == "-D" and process.args == "-R"] by process.pid, process.entity_id
 [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.parent.name == "sshd" and
  process.executable != null and not (
    process.executable in ("/usr/sbin/sshd", "/usr/sbin/unix_chkpwd", "/usr/bin/google_authorized_keys", "/usr/bin/fipscheck") or
    process.args like ("rsync*", "systemctl*", "/usr/sbin/unix_chkpwd", "/usr/bin/google_authorized_keys", "/usr/sbin/aad_certhandler*") or
    process.command_line like "sh -c /usr/bin/env -i PATH=*"
  )] by process.parent.pid, process.parent.entity_id
 [process where host.os.type == "linux" and event.action == "end" and process.name == "sshd" and process.exit_code != 0] by process.pid, process.entity_id
 [network where host.os.type == "linux" and event.type == "end" and event.action == "disconnect_received" and process.name == "sshd"] by process.pid, process.entity_id
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Modify Authentication Process
    * ID: T1556
    * Reference URL: [https://attack.mitre.org/techniques/T1556/](https://attack.mitre.org/techniques/T1556/)

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




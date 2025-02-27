---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-3-process-started-from-process-id-pid-file.html
---

# Process Started from Process ID (PID) File [prebuilt-rule-8-4-3-process-started-from-process-id-pid-file]

Identifies a new process starting from a process ID (PID), lock or reboot file within the temporary file storage paradigm (tmpfs) directory /var/run directory. On Linux, the PID files typically hold the process ID to track previous copies running and manage other tasks. Certain Linux malware use the /var/run directory for holding data, executables and other tasks, disguising itself or these files as legitimate PID files.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.sandflysecurity.com/blog/linux-file-masquerading-and-malicious-pids-sandfly-1-2-6-update/](https://www.sandflysecurity.com/blog/linux-file-masquerading-and-malicious-pids-sandfly-1-2-6-update/)
* [https://twitter.com/GossiTheDog/status/1522964028284411907](https://twitter.com/GossiTheDog/status/1522964028284411907)
* [https://exatrack.com/public/Tricephalic_Hellkeeper.pdf](https://exatrack.com/public/Tricephalic_Hellkeeper.pdf)
* [https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor](https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor)

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Execution
* BPFDoor
* Elastic Endgame

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3589]

## Triage and analysis

## Investigating Process Started from Process ID (PID) File
Detection alerts from this rule indicate a process spawned from an executable masqueraded as a legitimate PID file which is very unusual and should not occur. Here are some possible avenues of investigation:
- Examine parent and child process relationships of the new process to determine if other processes are running.
- Examine the /var/run directory using Osquery to determine other potential PID files with unsually large file sizes, indicative of it being an executable: "SELECT f.size, f.uid, f.type, f.path from file f WHERE path like '/var/run/%%';"
- Examine the reputation of the SHA256 hash from the PID file in a database like VirusTotal to identify additional pivots and artifacts for investigation.

## Rule query [_rule_query_4323]

```js
process where event.type == "start" and user.id == "0" and process.executable regex~ """/var/run/\w+\.(pid|lock|reboot)"""
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)




---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-1-1-abnormal-process-id-or-lock-file-created.html
---

# Abnormal Process ID or Lock File Created [prebuilt-rule-8-1-1-abnormal-process-id-or-lock-file-created]

Identifies the creation of a Process ID (PID), lock or reboot file created in temporary file storage paradigm (tmpfs) directory /var/run. On Linux, the PID files typically hold the process ID to track previous copies running and manage other tasks. Certain Linux malware use the /var/run directory for holding data, executables and other tasks, disguising itself or these files as legitimate PID files.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 43

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.sandflysecurity.com/blog/linux-file-masquerading-and-malicious-pids-sandfly-1-2-6-update/](https://www.sandflysecurity.com/blog/linux-file-masquerading-and-malicious-pids-sandfly-1-2-6-update/)
* [https://twitter.com/GossiTheDog/status/1522964028284411907](https://twitter.com/GossiTheDog/status/1522964028284411907)
* [https://exatrack.com/public/Tricephalic_Hellkeeper.pdf](https://exatrack.com/public/Tricephalic_Hellkeeper.pdf)

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Execution
* BPFDoor

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1683]

## Triage and analysis

## Investigating Abnormal Process ID or Lock File Created
Detection alerts from this rule indicate that an unusual PID file was created and could potentially have alternate purposes during an intrusion.  Here are some possible avenues of investigation:
- Run the following in Osquery to quickly identify unsual PID file size: "SELECT f.size, f.uid, f.type, f.path from file f WHERE path like '/var/run/%pid';"
- Examine the history of this file creation and from which process it was created by using the "lsof" command.
- Examine the contents of the PID file itself, simply by running the "cat" command to determine if the expected process ID integer exists and if not, the PID file is not legitimate.
- Examine the reputation of the SHA256 hash from the PID file in a database like VirusTotal to identify additional pivots and artifacts for investigation.

## Rule query [_rule_query_1952]

```js
/* add file size filters when data is available */
file where event.type == "creation" and user.id == "0" and
    file.path regex~ """/var/run/\w+\.(pid|lock|reboot)""" and file.extension in ("pid","lock","reboot") and

    /* handle common legitimate files */

    not file.name in (
    "auditd.pid",
    "python*",
    "apport.pid",
    "apport.lock",
    "kworker*",
    "gdm3.pid",
    "sshd.pid",
    "acpid.pid",
    "unattended-upgrades.lock",
    "unattended-upgrades.pid",
    "cmd.pid",
    "cron*.pid"
    )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Native API
    * ID: T1106
    * Reference URL: [https://attack.mitre.org/techniques/T1106/](https://attack.mitre.org/techniques/T1106/)




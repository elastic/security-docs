---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-6-1-abnormal-process-id-or-lock-file-created.html
---

# Abnormal Process ID or Lock File Created [prebuilt-rule-8-6-1-abnormal-process-id-or-lock-file-created]

Identifies the creation of a Process ID (PID), lock or reboot file created in temporary file storage paradigm (tmpfs) directory /var/run. On Linux, the PID files typically hold the process ID to track previous copies running and manage other tasks. Certain Linux malware use the /var/run directory for holding data, executables and other tasks, disguising itself or these files as legitimate PID files.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*

**Severity**: medium

**Risk score**: 47

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
* Investigation Guide
* Elastic Endgame

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3743]

## Triage and analysis

## Investigating Abnormal Process ID or Lock File Created

Linux applications may need to save their process identification number (PID) for various purposes: from signaling that a program is running to serving as a signal that a previous instance of an application didn't exit successfully. PID files contain its creator process PID in an integer value.

Linux lock files are used to coordinate operations in files so that conflicts and race conditions are prevented.

This rule identifies the creation of PID, lock, or reboot files in the /var/run/ directory. Attackers can masquerade malware, payloads, staged data for exfiltration, and more as legitimate PID files.

### Possible investigation steps

- Retrieve the file and determine if it is malicious:
    - Check the contents of the PID files. They should only contain integer strings.
    - Check the file type of the lock and PID files to determine if they are executables. This is only observed in     malicious files.
    - Check the size of the subject file. Legitimate PID files should be under 10 bytes.
    - Check if the lock or PID file has high entropy. This typically indicates an encrypted payload.
        - Analysts can use tools like `ent` to measure entropy.
    - Examine the reputation of the SHA-256 hash in the PID file. Use a database like VirusTotal to identify additional pivots and artifacts for investigation.
- Trace the file's creation to ensure it came from a legitimate or authorized process.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Investigate any abnormal account behavior, such as command executions, file creations or modifications, and network connections.
- Investigate any abnormal behavior by the subject process such as network connections, file modifications, and any spawned child processes.

## False positive analysis

- False positives can appear if the PID file is legitimate and holding a process ID as intended. If the PID file is an executable or has a file size that's larger than 10 bytes, it should be ruled suspicious.
- If this activity is expected and noisy in your environment, consider adding exceptions — preferably with a combination of file name and process executable conditions.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
- Block the identified indicators of compromise (IoCs).
- Take actions to terminate processes and connections used by the attacker.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

## Rule query [_rule_query_4572]

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
    "cron*.pid",
    "yum.pid",
    "netconfig.pid",
    "docker.pid",
    "atd.pid",
    "lfd.pid",
    "atop.pid",
    "nginx.pid",
    "dhclient.pid",
    "smtpd.pid",
    "stunnel.pid",
    "1_waagent.pid"
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




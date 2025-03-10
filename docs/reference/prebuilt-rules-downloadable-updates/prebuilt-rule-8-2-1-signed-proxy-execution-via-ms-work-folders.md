---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-signed-proxy-execution-via-ms-work-folders.html
---

# Signed Proxy Execution via MS Work Folders [prebuilt-rule-8-2-1-signed-proxy-execution-via-ms-work-folders]

Identifies the use of Windows Work Folders to execute a potentially masqueraded control.exe file in the current working directory. Misuse of Windows Work Folders could indicate malicious activity.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/windows-server/storage/work-folders/work-folders-overview](https://docs.microsoft.com/en-us/windows-server/storage/work-folders/work-folders-overview)
* [https://twitter.com/ElliotKillick/status/1449812843772227588](https://twitter.com/ElliotKillick/status/1449812843772227588)
* [https://lolbas-project.github.io/lolbas/Binaries/WorkFolders/](https://lolbas-project.github.io/lolbas/Binaries/WorkFolders/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion

**Version**: 4

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2148]

## Triage and analysis

## Investigating Signed Proxy Execution via MS Work Folders

Work Folders is a role service for file servers running Windows Server that provides a consistent way for users to access
their work files from their PCs and devices. This allows users to store work files and access them from anywhere. When
called, Work Folders will automatically execute any Portable Executable (PE) named control.exe as an argument before
accessing the synced share.

Using Work Folders to execute a masqueraded control.exe could allow an adversary to bypass application controls and
increase privileges.

### Possible investigation steps

- Investigate the process tree starting with parent process WorkFolders.exe and child process control.exe to determine
if other child processes spawned during execution.
- Trace the activity related to the control.exe binary to identify any continuing intrusion activity on the host.
- Examine the location of the WorkFolders.exe binary to determine if it was copied to the location of the control.exe
binary. It resides in the System32 directory by default.
- Review the control.exe binary executed with Work Folders to determine maliciousness such as additional host activity
or network traffic.
- Determine if control.exe was synced to sync share, indicating potential lateral movement.
- Review how control.exe was originally delivered on the host, such as emailed, downloaded from the web, or written to
disk from a separate binary.

## False positive analysis

- Windows Work Folders are used legitimately by end users and administrators for file sharing and syncing but not in the
instance where a suspicious control.exe is passed as an argument.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- Review the Work Folders synced share to determine if the control.exe was shared and if so remove it.
- If no lateral movement was identified during investigation, take the affected host offline if possible and remove the
control.exe binary as well as any additional artifacts identified during investigation.
- Review integrating Windows Information Protection (WIP) to enforce data protection by encrypting the data on PCs using
Work Folders.
- Confirm with the user whether this was expected or not, and reset their password.

## Rule query [_rule_query_2438]

```js
process where event.type in ("start","process_started")
    and process.name : "control.exe" and process.parent.name : "WorkFolders.exe"
    and not process.executable : ("?:\\Windows\\System32\\control.exe", "?:\\Windows\\SysWOW64\\control.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)




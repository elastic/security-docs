---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-attempt-to-mount-smb-share-via-command-line.html
---

# Attempt to Mount SMB Share via Command Line [prebuilt-rule-8-3-3-attempt-to-mount-smb-share-via-command-line]

Identifies the execution of macOS built-in commands to mount a Server Message Block (SMB) network share. Adversaries may use valid accounts to interact with a remote network share using SMB.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.freebsd.org/cgi/man.cgi?mount_smbfs](https://www.freebsd.org/cgi/man.cgi?mount_smbfs)
* [https://ss64.com/osx/mount.html](https://ss64.com/osx/mount.md)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Lateral Movement

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2969]



## Rule query [_rule_query_3438]

```js
process where event.type in ("start", "process_started") and
  (
    process.name : "mount_smbfs" or
    (process.name : "open" and process.args : "smb://*") or
    (process.name : "mount" and process.args : "smbfs") or
    (process.name : "osascript" and process.command_line : "osascript*mount volume*smb://*")
  ) and
  not process.parent.executable : "/Applications/Google Drive.app/Contents/MacOS/Google Drive"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)

* Sub-technique:

    * Name: SMB/Windows Admin Shares
    * ID: T1021.002
    * Reference URL: [https://attack.mitre.org/techniques/T1021/002/](https://attack.mitre.org/techniques/T1021/002/)




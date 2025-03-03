---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-1-1-suspicious-remote-registry-access-via-sebackupprivilege.html
---

# Suspicious Remote Registry Access via SeBackupPrivilege [prebuilt-rule-8-1-1-suspicious-remote-registry-access-via-sebackupprivilege]

Identifies remote access to the registry using an account with Backup Operators group membership. This may indicate an attempt to exfiltrate credentials by dumping the Security Account Manager (SAM) registry hive in preparation for credential access and privileges elevation.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-system.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/mpgn/BackupOperatorToDA](https://github.com/mpgn/BackupOperatorToDA)
* [https://raw.githubusercontent.com/Wh04m1001/Random/main/BackupOperators.cpp](https://raw.githubusercontent.com/Wh04m1001/Random/main/BackupOperators.cpp)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Lateral Movement
* Credential Access

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1739]

## Config

The 'Audit Detailed File Share' audit policy is required be configured (Success) on Domain Controllers and Sensitive Windows Servers.
Steps to implement the logging policy with with Advanced Audit Configuration:
```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Policies Configuration >
Audit Policies >
Object Access >
Audit Detailed File Share (Success)
```

The 'Special Logon' audit policy must be configured (Success).
Steps to implement the logging policy with with Advanced Audit Configuration:
```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Policies Configuration >
Audit Policies >
Logon/Logoff >
Special Logon (Success)
```

## Rule query [_rule_query_2013]

```js
sequence by host.id, winlog.event_data.SubjectLogonId with maxspan=1m
 [iam where event.action == "logged-in-special"  and
  winlog.event_data.PrivilegeList : "SeBackupPrivilege"]
 [any where event.action == "Detailed File Share" and winlog.event_data.RelativeTargetName : "winreg"]
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

    * Name: Security Account Manager
    * ID: T1003.002
    * Reference URL: [https://attack.mitre.org/techniques/T1003/002/](https://attack.mitre.org/techniques/T1003/002/)

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)




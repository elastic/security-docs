---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-suspicious-remote-registry-access-via-sebackupprivilege.html
---

# Suspicious Remote Registry Access via SeBackupPrivilege [prebuilt-rule-8-4-2-suspicious-remote-registry-access-via-sebackupprivilege]

Identifies remote access to the registry using an account with Backup Operators group membership. This may indicate an attempt to exfiltrate credentials by dumping the Security Account Manager (SAM) registry hive in preparation for credential access and privileges elevation.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-system.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/mpgn/BackupOperatorToDA](https://github.com/mpgn/BackupOperatorToDA)
* [https://raw.githubusercontent.com/Wh04m1001/Random/main/BackupOperators.cpp](https://raw.githubusercontent.com/Wh04m1001/Random/main/BackupOperators.cpp)
* [https://www.elastic.co/security-labs/detect-credential-access](https://www.elastic.co/security-labs/detect-credential-access)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Lateral Movement
* Credential Access
* Investigation Guide
* Active Directory

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3382]

## Triage and analysis

## Investigating Suspicious Remote Registry Access via SeBackupPrivilege

SeBackupPrivilege is a privilege that allows file content retrieval, designed to enable users to create backup copies of the system. Since it is impossible to make a backup of something you cannot read, this privilege comes at the cost of providing the user with full read access to the file system. This privilege must bypass any access control list (ACL) placed in the system.

This rule identifies remote access to the registry using an account with Backup Operators group membership. This may indicate an attempt to exfiltrate credentials by dumping the Security Account Manager (SAM) registry hive in preparation for credential access and privileges elevation.

### Possible investigation steps

- Identify the user account that performed the action and whether it should perform this kind of action.
- Investigate the activities done by the subject user the login session. The field `winlog.event_data.SubjectLogonId` can be used to get this data.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Contact the account owner and confirm whether they are aware of this activity.
- Investigate abnormal behaviors observed by the subject user such as network connections, registry or file modifications, and processes created.
- Investigate if the registry file was retrieved or exfiltrated.

## False positive analysis

- If this activity is expected and noisy in your environment, benign true positives (B-TPs) can be added as exceptions if necessary.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Limit or disable the involved user account to prevent further post-compromise behavior.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

## Rule query [_rule_query_4023]

```js
sequence by winlog.computer_name, winlog.event_data.SubjectLogonId with maxspan=1m
 [iam where event.action == "logged-in-special"  and
  winlog.event_data.PrivilegeList : "SeBackupPrivilege" and

  /* excluding accounts with existing privileged access */
  not winlog.event_data.PrivilegeList : "SeDebugPrivilege"]
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




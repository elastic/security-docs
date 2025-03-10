---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-windows-registry-file-creation-in-smb-share.html
---

# Windows Registry File Creation in SMB Share [prebuilt-rule-8-4-2-windows-registry-file-creation-in-smb-share]

Identifies the creation or modification of a medium-size registry hive file on a Server Message Block (SMB) share, which may indicate an exfiltration attempt of a previously dumped Security Account Manager (SAM) registry hive for credential extraction on an attacker-controlled system.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/security-labs/detect-credential-access](https://www.elastic.co/security-labs/detect-credential-access)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Lateral Movement
* Credential Access
* Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3369]

## Triage and analysis

## Investigating Windows Registry File Creation in SMB Share

Dumping registry hives is a common way to access credential information. Some hives store credential material, as is the case for the SAM hive, which stores locally cached credentials (SAM secrets), and the SECURITY hive, which stores domain cached credentials (LSA secrets). Dumping these hives in combination with the SYSTEM hive enables the attacker to decrypt these secrets.

Attackers can try to evade detection on the host by transferring this data to a system that is not monitored to be parsed and decrypted. This rule identifies the creation or modification of a medium-size registry hive file on an SMB share, which may indicate this kind of exfiltration attempt.

### Possible investigation steps

- Investigate other alerts associated with the user/source host during the past 48 hours.
- Identify the user account that performed the action and whether it should perform this kind of action.
- Contact the account owner and confirm whether they are aware of this activity.
- Inspect the source host for suspicious or abnormal behaviors in the alert timeframe.
- Capture the registry file(s) to determine the extent of the credential compromise in an eventual incident response.

## False positive analysis

- Administrators can export registry hives for backup purposes. Check whether the user should be performing this kind of activity and is aware of it.

## Related rules

- Credential Acquisition via Registry Hive Dumping - a7e7bfa3-088e-4f13-b29e-3986e0e756b8

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved hosts to prevent further post-compromise behavior.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
- Reimage the host operating system and restore compromised files to clean versions.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

## Rule query [_rule_query_4008]

```js
file where event.type == "creation" and
 /* regf file header */
 file.Ext.header_bytes : "72656766*" and file.size >= 30000 and
 process.pid == 4 and user.id : ("S-1-5-21*", "S-1-12-1-*")
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

* Sub-technique:

    * Name: SMB/Windows Admin Shares
    * ID: T1021.002
    * Reference URL: [https://attack.mitre.org/techniques/T1021/002/](https://attack.mitre.org/techniques/T1021/002/)




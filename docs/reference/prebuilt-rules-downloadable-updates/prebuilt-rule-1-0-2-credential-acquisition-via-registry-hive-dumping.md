---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-credential-acquisition-via-registry-hive-dumping.html
---

# Credential Acquisition via Registry Hive Dumping [prebuilt-rule-1-0-2-credential-acquisition-via-registry-hive-dumping]

Identifies attempts to export a registry hive which may contain credentials using the Windows reg.exe tool.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://medium.com/threatpunter/detecting-attempts-to-steal-passwords-from-the-registry-7512674487f8](https://medium.com/threatpunter/detecting-attempts-to-steal-passwords-from-the-registry-7512674487f8)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Credential Access

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1511]

## Triage and analysis

## Investigating Credential Acquisition via Registry Hive Dumping

Dumping registry hives is a common way to access credential information as some hives store credential material.

For example, the SAM hive stores locally cached credentials (SAM Secrets), and the SECURITY hive stores domain cached
credentials (LSA secrets).

Dumping these hives in combination with the SYSTEM hive enables the attacker to decrypt these secrets.

This rule identifies the usage of `reg.exe` to dump SECURITY and/or SAM hives, which potentially indicates the
compromise of the credentials stored in the host.

### Possible investigation steps

- Investigate script execution chain (parent process tree).
- Confirm whether the involved account should perform this kind of operation.
- Investigate other alerts related to the user/host in the last 48 hours.
- Investigate if the file was exfiltrated or processed locally by other tools.
- Scope potentially compromised accounts. Analysts can do this by searching for login events (e.g., 4624) to the target
host.

## False positive analysis

- Administrators can export registry hives for backup purposes using command line tools like `reg.exe`. Check whether
the user is legitamitely performing this kind of activity.

## Related rules

- Registry Hive File Creation via SMB - a4c7473a-5cb4-4bc1-9d06-e4a75adbc494

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved hosts to prevent further post-compromise behavior.
- Scope compromised credentials and disable affected accounts.
- Reset passwords for potentially compromised user and service accounts (Email, services, CRMs, etc.).
- Reimage the host operating system and restore compromised files to clean versions.

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1747]

```js
process where event.type in ("start", "process_started") and
 process.pe.original_file_name == "reg.exe" and
 process.args : ("save", "export") and
 process.args : ("hklm\\sam", "hklm\\security")
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

* Sub-technique:

    * Name: LSA Secrets
    * ID: T1003.004
    * Reference URL: [https://attack.mitre.org/techniques/T1003/004/](https://attack.mitre.org/techniques/T1003/004/)




---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-modification-of-boot-configuration.html
---

# Modification of Boot Configuration [prebuilt-rule-1-0-2-modification-of-boot-configuration]

Identifies use of `bcdedit.exe` to delete boot configuration data. This tactic is sometimes used as by malware or an attacker as a destructive technique.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Impact

**Version**: 10

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1606]

## Triage and analysis

## Investigating Modification of Boot Configuration

Boot entry parameters, or boot parameters, are optional, system-specific settings that represent configuration options.
These are stored in a boot configuration data (BCD) store, and administrators can use utilities like `bcdedit.exe` to
configure these.

This rule identifies the usage of `bcdedit.exe` to:

- Disable Windows Error Recovery (recoveryenabled).
- Ignore errors if there is a failed boot, failed shutdown, or failed checkpoint (bootstatuspolicy ignoreallfailures).

These are common steps in destructive attacks by adversaries leveraging ransomware.

### Possible investigation steps

- Investigate the script execution chain (parent process tree).
- Identify the user account that performed the action and whether it should perform this kind of action.
- Confirm whether the account owner is aware of the operation.
- Investigate other alerts related to the user/host in the last 48 hours.
- Check for similar behavior in other hosts on the environment.
- Check if any files on the host machine have been encrypted.

## False positive analysis

- The usage of these options is not inherently malicious. Administrators can modify these configurations to force a
machine to boot for troubleshooting or data recovery purposes.

## Related rules

- Deleting Backup Catalogs with Wbadmin - 581add16-df76-42bb-af8e-c979bfb39a59

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent destructive behavior, which is commonly associated with this activity.
- Reset the password of the involved accounts.
- If any other destructive action was identified on the host, it is recommended to prioritize the investigation and look
for ransomware preparation and execution activities.

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1855]

```js
process where event.type in ("start", "process_started") and
  (process.name : "bcdedit.exe" or process.pe.original_file_name == "bcdedit.exe") and
  (process.args : "/set" and process.args : "bootstatuspolicy" and process.args : "ignoreallfailures") or
  (process.args : "no" and process.args : "recoveryenabled")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Inhibit System Recovery
    * ID: T1490
    * Reference URL: [https://attack.mitre.org/techniques/T1490/](https://attack.mitre.org/techniques/T1490/)




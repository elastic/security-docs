---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-modification-of-amsienable-registry-key.html
---

# Modification of AmsiEnable Registry Key [prebuilt-rule-1-0-2-modification-of-amsienable-registry-key]

Identifies modifications of the AmsiEnable registry key to 0, which disables the Antimalware Scan Interface (AMSI). An adversary can modify this key to disable AMSI protections.

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

* [https://hackinparis.com/data/slides/2019/talks/HIP2019-Dominic_Chell-Cracking_The_Perimeter_With_Sharpshooter.pdf](https://hackinparis.com/data/slides/2019/talks/HIP2019-Dominic_Chell-Cracking_The_Perimeter_With_Sharpshooter.pdf)
* [https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1527]

## Triage and analysis

## Investigating Modification of AmsiEnable Registry Key

The Windows Antimalware Scan Interface (AMSI) is a versatile interface standard that allows your applications and
services to integrate with any antimalware product that's present on a machine. AMSI provides integration with multiple
Windows components, ranging from User Account Control (UAC) to VBA Macros.

Since AMSI is widely used across security products for increased visibility, attackers can disable it to evade
detections that rely on it.

This rule monitors the modifications to the Software\Microsoft\Windows Script\Settings\AmsiEnable registry key.

### Possible investigation steps

- Identify the user that performed the action.
- Check whether this user should be doing this kind of activity.
- Investigate program execution chain (parent process tree).
- Investigate other alerts related to the user/host in the last 48 hours.
- Investigate the execution of scripts and macros after the registry modification.
- Retrieve script/office files:
  - Use a sandboxed malware analysis system to perform analysis.
    - Observe attempts to contact external domains and addresses.
  - Use the PowerShell Get-FileHash cmdlet to get the SHA-256 hash value of the file.
    - Search for the existence of this file in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.
- Use process name, command line, and file hash to search for occurrences on other hosts.

## False positive analysis

- This modification should not happen legitimately. Any potential benign true positive (B-TP) should be mapped and
monitored by the security team, as these modifications expose the host to malware infections.

## Related rules

- Microsoft Windows Defender Tampering - fe794edd-487f-4a90-b285-3ee54f2af2d3

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved hosts to prevent further post-compromise behavior.
- If malware was found, implement temporary network rules, procedures, and segmentation required to contain it.
- Delete or set the key to its default value.


## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1764]

```js
registry where event.type in ("creation", "change") and
  registry.path : (
    "HKEY_USERS\\*\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable",
    "HKU\\*\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable"
  ) and
  registry.data.strings: ("0", "0x00000000")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Sub-technique:

    * Name: Disable or Modify Tools
    * ID: T1562.001
    * Reference URL: [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)




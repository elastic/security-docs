---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-modification-of-amsienable-registry-key.html
---

# Modification of AmsiEnable Registry Key [prebuilt-rule-8-4-2-modification-of-amsienable-registry-key]

Identifies modifications of the AmsiEnable registry key to 0, which disables the Antimalware Scan Interface (AMSI). An adversary can modify this key to disable AMSI protections.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*
* endgame-*

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
* Investigation Guide
* Elastic Endgame

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3387]

## Triage and analysis

## Investigating Modification of AmsiEnable Registry Key

The Windows Antimalware Scan Interface (AMSI) is a versatile interface standard that allows your applications and services to integrate with any antimalware product that's present on a machine. AMSI provides integration with multiple Windows components, ranging from User Account Control (UAC) to VBA Macros.

Since AMSI is widely used across security products for increased visibility, attackers can disable it to evade detections that rely on it.

This rule monitors the modifications to the Software\Microsoft\Windows Script\Settings\AmsiEnable registry key.

### Possible investigation steps

- Identify the user account that performed the action and whether it should perform this kind of action.
- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Investigate the execution of scripts and macros after the registry modification.
- Retrieve scripts or Microsoft Office files and determine if they are malicious:
  - Use a private sandboxed malware analysis system to perform analysis.
    - Observe and collect information about the following activities:
      - Attempts to contact external domains and addresses.
      - File and registry access, modification, and creation activities.
      - Service creation and launch activities.
      - Scheduled task creation.
  - Use the PowerShell Get-FileHash cmdlet to get the files' SHA-256 hash values.
    - Search for the existence and reputation of the hashes in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.
- Use process name, command line, and file hash to search for occurrences on other hosts.

## False positive analysis

- This modification should not happen legitimately. Any potential benign true positive (B-TP) should be mapped and monitored by the security team, as these modifications expose the host to malware infections.

## Related rules

- Microsoft Windows Defender Tampering - fe794edd-487f-4a90-b285-3ee54f2af2d3

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved hosts to prevent further post-compromise behavior.
- If the triage identified malware, search the environment for additional compromised hosts.
  - Implement temporary network rules, procedures, and segmentation to contain the malware.
  - Stop suspicious processes.
  - Immediately block the identified indicators of compromise (IoCs).
  - Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
- Remove and block malicious artifacts identified during triage.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
- Delete or set the key to its default value.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

## Rule query [_rule_query_4028]

```js
registry where event.type in ("creation", "change") and
  registry.path : (
    "HKEY_USERS\\*\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable",
    "HKU\\*\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable",
    "\\REGISTRY\\USER\\*\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable"
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




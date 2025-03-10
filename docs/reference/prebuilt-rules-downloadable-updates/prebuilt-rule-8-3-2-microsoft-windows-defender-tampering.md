---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-microsoft-windows-defender-tampering.html
---

# Microsoft Windows Defender Tampering [prebuilt-rule-8-3-2-microsoft-windows-defender-tampering]

Identifies when one or more features on Microsoft Defender are disabled. Adversaries may disable or tamper with Microsoft Defender features to evade detection and conceal malicious behavior.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/](https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/)
* [https://www.tenforums.com/tutorials/32236-enable-disable-microsoft-defender-pua-protection-windows-10-a.html](https://www.tenforums.com/tutorials/32236-enable-disable-microsoft-defender-pua-protection-windows-10-a.md)
* [https://www.tenforums.com/tutorials/104025-turn-off-core-isolation-memory-integrity-windows-10-a.html](https://www.tenforums.com/tutorials/104025-turn-off-core-isolation-memory-integrity-windows-10-a.md)
* [https://www.tenforums.com/tutorials/105533-enable-disable-windows-defender-exploit-protection-settings.html](https://www.tenforums.com/tutorials/105533-enable-disable-windows-defender-exploit-protection-settings.md)
* [https://www.tenforums.com/tutorials/123792-turn-off-tamper-protection-microsoft-defender-antivirus.html](https://www.tenforums.com/tutorials/123792-turn-off-tamper-protection-microsoft-defender-antivirus.md)
* [https://www.tenforums.com/tutorials/51514-turn-off-microsoft-defender-periodic-scanning-windows-10-a.html](https://www.tenforums.com/tutorials/51514-turn-off-microsoft-defender-periodic-scanning-windows-10-a.md)
* [https://www.tenforums.com/tutorials/3569-turn-off-real-time-protection-microsoft-defender-antivirus.html](https://www.tenforums.com/tutorials/3569-turn-off-real-time-protection-microsoft-defender-antivirus.md)
* [https://www.tenforums.com/tutorials/99576-how-schedule-scan-microsoft-defender-antivirus-windows-10-a.html](https://www.tenforums.com/tutorials/99576-how-schedule-scan-microsoft-defender-antivirus-windows-10-a.md)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion
* has_guide

**Version**: 101

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2460]

## Triage and analysis

## Investigating Microsoft Windows Defender Tampering

Microsoft Windows Defender is an antivirus product built into Microsoft Windows, which makes it popular across multiple
environments. Disabling it is a common step in threat actor playbooks.

This rule monitors the registry for modifications that disable Windows Defender features.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files
for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Validate the activity is not related to planned patches, updates, network administrator activity, or legitimate
software installations.
- Identify the user account that performed the action and whether it should perform this kind of action.
- Contact the account owner and confirm whether they are aware of this activity.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Examine which features have been disabled, and check if this operation is done under change management and approved
according to the organization's policy.

## False positive analysis

- This mechanism can be used legitimately. Analysts can dismiss the alert if the administrator is aware of the activity,
the configuration is justified (for example, it is being used to deploy other security solutions or troubleshooting),
and no other suspicious activity has been observed.

## Related rules

- Windows Defender Disabled via Registry Modification - 2ffa1f1e-b6db-47fa-994b-1512743847eb
- Disabling Windows Defender Security Settings via PowerShell - c8cccb06-faf2-4cd5-886e-2c9636cfcb87

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved hosts to prevent further post-compromise behavior.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business
systems, and web services.
- Take actions to restore the appropriate Windows Defender antivirus configurations.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and
malware components.
- Review the privileges assigned to the user to ensure that the least privilege principle is being followed.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_2828]

```js
registry where event.type in ("creation", "change") and
  (registry.path : "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\PUAProtection" and
  registry.data.strings : ("0", "0x00000000")) or
  (registry.path : "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\App and Browser protection\\DisallowExploitProtectionOverride" and
  registry.data.strings : ("0", "0x00000000")) or
  (registry.path : "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware" and
  registry.data.strings : ("1", "0x00000001")) or
  (registry.path : "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Features\\TamperProtection" and
  registry.data.strings : ("0", "0x00000000")) or
  (registry.path : "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring" and
  registry.data.strings : ("1", "0x00000001")) or
  (registry.path : "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableIntrusionPreventionSystem" and
  registry.data.strings : ("1", "0x00000001")) or
  (registry.path : "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableScriptScanning" and
  registry.data.strings : ("1", "0x00000001")) or
  (registry.path : "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Controlled Folder Access\\EnableControlledFolderAccess" and
  registry.data.strings : ("0", "0x00000000")) or
  (registry.path : "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableIOAVProtection" and
  registry.data.strings : ("1", "0x00000001")) or
  (registry.path : "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Reporting\\DisableEnhancedNotifications" and
  registry.data.strings : ("1", "0x00000001")) or
  (registry.path : "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\SpyNet\\DisableBlockAtFirstSeen" and
  registry.data.strings : ("1", "0x00000001")) or
  (registry.path : "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\SpyNet\\SpynetReporting" and
  registry.data.strings : ("0", "0x00000000")) or
  (registry.path : "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\SpyNet\\SubmitSamplesConsent" and
  registry.data.strings : ("0", "0x00000000")) or
  (registry.path : "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableBehaviorMonitoring" and
  registry.data.strings : ("1", "0x00000001"))
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




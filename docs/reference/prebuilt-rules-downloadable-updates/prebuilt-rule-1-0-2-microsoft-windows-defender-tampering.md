---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-microsoft-windows-defender-tampering.html
---

# Microsoft Windows Defender Tampering [prebuilt-rule-1-0-2-microsoft-windows-defender-tampering]

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

**Version**: 3

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1557]

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1796]

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




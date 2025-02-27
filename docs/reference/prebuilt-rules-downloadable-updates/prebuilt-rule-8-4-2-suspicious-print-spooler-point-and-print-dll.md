---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-suspicious-print-spooler-point-and-print-dll.html
---

# Suspicious Print Spooler Point and Print DLL [prebuilt-rule-8-4-2-suspicious-print-spooler-point-and-print-dll]

Detects attempts to exploit a privilege escalation vulnerability (CVE-2020-1030) related to the print spooler service. Exploitation involves chaining multiple primitives to load an arbitrary DLL into the print spooler process running as SYSTEM.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.accenture.com/us-en/blogs/cyber-defense/discovering-exploiting-shutting-down-dangerous-windows-print-spooler-vulnerability](https://www.accenture.com/us-en/blogs/cyber-defense/discovering-exploiting-shutting-down-dangerous-windows-print-spooler-vulnerability)
* [https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Privilege%20Escalation/privesc_sysmon_cve_20201030_spooler.evtx](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Privilege%20Escalation/privesc_sysmon_cve_20201030_spooler.evtx)
* [https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-1030](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-1030)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Privilege Escalation

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4249]

```js
sequence by host.id with maxspan=30s
[registry where
 registry.path : "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers\\*\\SpoolDirectory" and
 registry.data.strings : "C:\\Windows\\System32\\spool\\drivers\\x64\\4"]
[registry where
 registry.path : "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers\\*\\CopyFiles\\Payload\\Module" and
 registry.data.strings : "C:\\Windows\\System32\\spool\\drivers\\x64\\4\\*"]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Exploitation for Privilege Escalation
    * ID: T1068
    * Reference URL: [https://attack.mitre.org/techniques/T1068/](https://attack.mitre.org/techniques/T1068/)




---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-registry-persistence-via-appinit-dll.html
---

# Registry Persistence via AppInit DLL [prebuilt-rule-8-4-2-registry-persistence-via-appinit-dll]

Attackers may maintain persistence by creating registry keys using AppInit DLLs. AppInit DLLs are loaded by every process using the common library, user32.dll.

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

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Persistence

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3513]



## Rule query [_rule_query_4191]

```js
registry where
   registry.path : ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_Dlls",
                    "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_Dlls") and
   not process.executable : ("C:\\Windows\\System32\\msiexec.exe",
                             "C:\\Windows\\SysWOW64\\msiexec.exe",
                             "C:\\Program Files\\Commvault\\ContentStore*\\Base\\cvd.exe",
                             "C:\\Program Files (x86)\\Commvault\\ContentStore*\\Base\\cvd.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)

* Sub-technique:

    * Name: AppInit DLLs
    * ID: T1546.010
    * Reference URL: [https://attack.mitre.org/techniques/T1546/010/](https://attack.mitre.org/techniques/T1546/010/)




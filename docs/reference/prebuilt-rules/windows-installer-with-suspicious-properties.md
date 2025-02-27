---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/windows-installer-with-suspicious-properties.html
---

# Windows Installer with Suspicious Properties [windows-installer-with-suspicious-properties]

Identifies the execution of an installer from an archive or with suspicious properties. Adversaries may abuse msiexec.exe to launch local or network accessible MSI files in an attempt to bypass application whitelisting.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-119m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://lolbas-project.github.io/lolbas/Binaries/Msiexec/](https://lolbas-project.github.io/lolbas/Binaries/Msiexec/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Rule Type: BBR
* Data Source: Elastic Defend

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1230]

```js
sequence with maxspan=1m
  [registry where host.os.type == "windows" and event.type == "change" and process.name : "msiexec.exe" and
   (
    (registry.value : "InstallSource" and
     registry.data.strings : ("?:\\Users\\*\\Temp\\Temp?_*.zip\\*",
                             "?:\\Users\\*\\*.7z\\*",
                             "?:\\Users\\*\\*.rar\\*")) or

    (registry.value : ("DisplayName", "ProductName") and registry.data.strings : "SetupTest")
    )]
  [process where host.os.type == "windows" and event.action == "start" and
    process.parent.name : "msiexec.exe" and
    not process.name : "msiexec.exe" and
    not (process.executable : ("?:\\Program Files (x86)\\*.exe", "?:\\Program Files\\*.exe") and process.code_signature.trusted == true)]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)

* Sub-technique:

    * Name: Msiexec
    * ID: T1218.007
    * Reference URL: [https://attack.mitre.org/techniques/T1218/007/](https://attack.mitre.org/techniques/T1218/007/)




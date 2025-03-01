---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/compression-dll-loaded-by-unusual-process.html
---

# Compression DLL Loaded by Unusual Process [compression-dll-loaded-by-unusual-process]

Identifies the image load of a compression DLL. Adversaries will often compress and encrypt data in preparation for exfiltration.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.library-*

**Severity**: low

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-119m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Collection
* Data Source: Elastic Defend
* Rule Type: BBR

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_237]

```js
library where host.os.type == "windows" and event.action == "load" and
  dll.name : ("System.IO.Compression.FileSystem.ni.dll", "System.IO.Compression.ni.dll") and
  not
  (
    (
      process.executable : (
        "?:\\Program Files\\*",
        "?:\\Program Files (x86)\\*",
        "?:\\Windows\\Microsoft.NET\\Framework*\\mscorsvw.exe",
        "?:\\Windows\\System32\\sdiagnhost.exe",
        "?:\\Windows\\System32\\inetsrv\\w3wp.exe",
        "?:\\Windows\\SysWOW64\\inetsrv\\w3wp.exe",
        "?:\\ProgramData\\Microsoft\\Windows Defender Advanced Threat Protection\\DataCollection\\*\\OpenHandleCollector.exe"
      ) and process.code_signature.trusted == true
    ) or
    (
      process.name : "NuGet.exe" and process.code_signature.trusted == true and user.id : ("S-1-5-18", "S-1-5-20")
    )
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Archive Collected Data
    * ID: T1560
    * Reference URL: [https://attack.mitre.org/techniques/T1560/](https://attack.mitre.org/techniques/T1560/)




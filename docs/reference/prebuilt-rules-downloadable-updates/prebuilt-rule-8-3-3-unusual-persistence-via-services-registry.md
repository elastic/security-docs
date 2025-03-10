---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-unusual-persistence-via-services-registry.html
---

# Unusual Persistence via Services Registry [prebuilt-rule-8-3-3-unusual-persistence-via-services-registry]

Identifies processes modifying the services registry key directly, instead of through the expected Windows APIs. This could be an indication of an adversary attempting to stealthily persist through abnormal service creation or modification of an existing service.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

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
* Persistence

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3718]

```js
registry where registry.path : ("HKLM\\SYSTEM\\ControlSet*\\Services\\*\\ServiceDLL", "HKLM\\SYSTEM\\ControlSet*\\Services\\*\\ImagePath") and
  not registry.data.strings : ("?:\\windows\\system32\\Drivers\\*.sys",
                               "\\SystemRoot\\System32\\drivers\\*.sys",
                               "\\??\\?:\\Windows\\system32\\Drivers\\*.SYS",
                               "system32\\DRIVERS\\USBSTOR") and
  not (process.name : "procexp??.exe" and registry.data.strings : "?:\\*\\procexp*.sys") and
  not process.executable : ("?:\\Program Files\\*.exe",
                            "?:\\Program Files (x86)\\*.exe",
                            "?:\\Windows\\System32\\svchost.exe",
                            "?:\\Windows\\winsxs\\*\\TiWorker.exe",
                            "?:\\Windows\\System32\\drvinst.exe",
                            "?:\\Windows\\System32\\services.exe",
                            "?:\\Windows\\System32\\msiexec.exe",
                            "?:\\Windows\\System32\\regsvr32.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Sub-technique:

    * Name: Windows Service
    * ID: T1543.003
    * Reference URL: [https://attack.mitre.org/techniques/T1543/003/](https://attack.mitre.org/techniques/T1543/003/)




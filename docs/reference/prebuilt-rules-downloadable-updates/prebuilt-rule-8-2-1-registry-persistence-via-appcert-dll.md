---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-registry-persistence-via-appcert-dll.html
---

# Registry Persistence via AppCert DLL [prebuilt-rule-8-2-1-registry-persistence-via-appcert-dll]

Detects attempts to maintain persistence by creating registry keys using AppCert DLLs. AppCert DLLs are loaded by every process using the common API functions to create processes.

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

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2204]



## Rule query [_rule_query_2494]

```js
registry where
/* uncomment once stable length(bytes_written_string) > 0 and */
  registry.path : "HKLM\\SYSTEM\\*ControlSet*\\Control\\Session Manager\\AppCertDLLs\\*"
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

    * Name: AppCert DLLs
    * ID: T1546.009
    * Reference URL: [https://attack.mitre.org/techniques/T1546/009/](https://attack.mitre.org/techniques/T1546/009/)




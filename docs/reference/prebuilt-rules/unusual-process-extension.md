---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unusual-process-extension.html
---

# Unusual Process Extension [unusual-process-extension]

Identifies processes running with unusual extensions that are not typically valid for Windows executables.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*

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
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Rule Type: BBR

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1188]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.executable : "?*" and
  not process.name : ("*.exe", "*.com", "*.scr", "*.tmp", "*.dat") and
  not process.executable :
    (
      "MemCompression",
      "Registry",
      "vmmem",
      "vmmemWSL",
      "?:\\Program Files\\Dell\\SupportAssistAgent\\*.p5x",
      "?:\\Program Files\\Docker\\Docker\\com.docker.service",
      "?:\\Users\\*\\AppData\\Local\\Intel\\AGS\\Libs\\AGSRunner.bin",
      "\\Device\\Mup\\*\\Software Management\\Select.Html.dep",
      "?:\\DJJApplications\\MedicalRecords\\bin\\Select.Html.dep",
      "?:\\ProgramData\\Software Management\\Select.Html.dep",
      "?:\\Program Files (x86)\\EnCase Applications\\Examiner Service\\EnCase64\\enhkey.dll",
      "?:\\Program Files (x86)\\Panda Security\\WAC\\PSNAEInj64.dll",
      "?:\\Program Files (x86)\\Johnson Controls\\LicenseActivator\\crp32002.ngn"
    ) and
  not (
    (process.name : "C9632CF058AE4321B6B0B5EA39B710FE" and process.code_signature.subject_name == "Dell Inc") or
    (process.name : "*.upd" and process.code_signature.subject_name == "Bloomberg LP") or
    (process.name: "FD552E21-686E-413C-931D-3B82A9D29F3B" and process.code_signature.subject_name: "Adobe Inc.") or
    (process.name: "3B91051C-AE82-43C9-BCEF-0309CD2DD9EB" and process.code_signature.subject_name: "McAfee, LLC") or
    (process.name: "soffice.bin" and process.code_signature.subject_name: "The Document Foundation") or
    (process.name: ("VeeamVixProxy_*", "{????????-????-????-????-????????????}") and process.code_signature.subject_name: "Veeam Software Group GmbH") or
    (process.name: "1cv8p64.bin" and process.code_signature.subject_name: "LLC 1C-Soft") or
    (process.name: "AGSRunner.bin" and process.code_signature.subject_name: "Intel Corporation")
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Masquerading
    * ID: T1036
    * Reference URL: [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)

* Sub-technique:

    * Name: Masquerade File Type
    * ID: T1036.008
    * Reference URL: [https://attack.mitre.org/techniques/T1036/008/](https://attack.mitre.org/techniques/T1036/008/)




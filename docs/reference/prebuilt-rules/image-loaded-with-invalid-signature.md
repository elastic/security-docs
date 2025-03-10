---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/image-loaded-with-invalid-signature.html
---

# Image Loaded with Invalid Signature [image-loaded-with-invalid-signature]

Identifies binaries that are loaded and with an invalid code signature. This may indicate an attempt to masquerade as a signed binary.

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
* Tactic: Defense Evasion
* Rule Type: BBR
* Data Source: Elastic Defend

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_455]

```js
library where host.os.type == "windows" and event.action == "load" and
  dll.code_signature.status : ("errorUntrustedRoot", "errorBadDigest", "errorUntrustedRoot") and
  (dll.Ext.relative_file_creation_time <= 500 or dll.Ext.relative_file_name_modify_time <= 500) and
  not startswith~(dll.name, process.name) and
  not dll.path : (
    "?:\\Windows\\System32\\DriverStore\\FileRepository\\*"
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

    * Name: Invalid Code Signature
    * ID: T1036.001
    * Reference URL: [https://attack.mitre.org/techniques/T1036/001/](https://attack.mitre.org/techniques/T1036/001/)




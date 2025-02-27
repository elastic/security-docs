---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-7-1-untrusted-driver-loaded.html
---

# Untrusted Driver Loaded [prebuilt-rule-8-7-1-untrusted-driver-loaded]

Identifies attempt to load an untrusted driver. Adversaries may modify code signing policies to enable execution of unsigned or self-signed code.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/hfiref0x/TDL](https://github.com/hfiref0x/TDL)
* [https://docs.microsoft.com/en-us/previous-versions/windows/hardware/design/dn653559(v=vs.85)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/windows/hardware/design/dn653559(v=vs.85)?redirectedfrom=MSDN)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Defense Evasion

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4666]

```js
library where process.pid == 4 and
  dll.code_signature.trusted != true and
  not dll.code_signature.status : ("errorExpired", "errorRevoked")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Subvert Trust Controls
    * ID: T1553
    * Reference URL: [https://attack.mitre.org/techniques/T1553/](https://attack.mitre.org/techniques/T1553/)

* Sub-technique:

    * Name: Code Signing Policy Modification
    * ID: T1553.006
    * Reference URL: [https://attack.mitre.org/techniques/T1553/006/](https://attack.mitre.org/techniques/T1553/006/)




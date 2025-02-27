---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-sip-provider-modification.html
---

# SIP Provider Modification [prebuilt-rule-1-0-2-sip-provider-modification]

Identifies modifications to the registered Subject Interface Package (SIP) providers. SIP providers are used by the Windows cryptographic system to validate file signatures on the system. This may be an attempt to bypass signature validation checks or inject code into critical processes.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/mattifestation/PoCSubjectInterfacePackage](https://github.com/mattifestation/PoCSubjectInterfacePackage)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1803]

```js
registry where event.type:"change" and
  registry.path: (
    "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllPutSignedDataMsg\\{*}\\Dll",
    "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllPutSignedDataMsg\\{*}\\Dll",
    "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\Providers\\Trust\\FinalPolicy\\{*}\\$Dll",
    "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\Providers\\Trust\\FinalPolicy\\{*}\\$Dll"
    ) and
  registry.data.strings:"*.dll"
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

    * Name: SIP and Trust Provider Hijacking
    * ID: T1553.003
    * Reference URL: [https://attack.mitre.org/techniques/T1553/003/](https://attack.mitre.org/techniques/T1553/003/)




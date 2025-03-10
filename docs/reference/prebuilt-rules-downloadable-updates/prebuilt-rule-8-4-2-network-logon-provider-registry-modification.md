---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-network-logon-provider-registry-modification.html
---

# Network Logon Provider Registry Modification [prebuilt-rule-8-4-2-network-logon-provider-registry-modification]

Identifies the modification of the network logon provider registry. Adversaries may register a rogue network logon provider module for persistence and/or credential access via intercepting the authentication credentials in clear text during user logon.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/gtworek/PSBits/tree/master/PasswordStealing/NPPSpy](https://github.com/gtworek/PSBits/tree/master/PasswordStealing/NPPSpy)
* [https://docs.microsoft.com/en-us/windows/win32/api/npapi/nf-npapi-nplogonnotify](https://docs.microsoft.com/en-us/windows/win32/api/npapi/nf-npapi-nplogonnotify)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Persistence
* Credential Access
* Elastic Endgame

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4009]

```js
registry where registry.data.strings != null and
 registry.path : (
    "HKLM\\SYSTEM\\*ControlSet*\\Services\\*\\NetworkProvider\\ProviderPath",
    "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Services\\*\\NetworkProvider\\ProviderPath"
 ) and
 /* Excluding default NetworkProviders RDPNP, LanmanWorkstation and webclient. */
 not ( user.id : "S-1-5-18" and
       registry.data.strings in
                ("%SystemRoot%\\System32\\ntlanman.dll",
                 "%SystemRoot%\\System32\\drprov.dll",
                 "%SystemRoot%\\System32\\davclnt.dll")
      )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Modify Authentication Process
    * ID: T1556
    * Reference URL: [https://attack.mitre.org/techniques/T1556/](https://attack.mitre.org/techniques/T1556/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)




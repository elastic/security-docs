---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-potential-local-ntlm-relay-via-http.html
---

# Potential Local NTLM Relay via HTTP [prebuilt-rule-8-4-2-potential-local-ntlm-relay-via-http]

Identifies attempt to coerce a local NTLM authentication via HTTP using the Windows Printer Spooler service as a target. An adversary may use this primitive in combination with other techniques to elevate privileges on a compromised system.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*
* endgame-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/med0x2e/NTLMRelay2Self](https://github.com/med0x2e/NTLMRelay2Self)
* [https://github.com/topotam/PetitPotam](https://github.com/topotam/PetitPotam)
* [https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Credential Access
* Elastic Endgame

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4013]

```js
process where event.type == "start" and
  process.name : "rundll32.exe" and

  /* Rundll32 WbeDav Client  */
  process.args : ("?:\\Windows\\System32\\davclnt.dll,DavSetCookie", "?:\\Windows\\SysWOW64\\davclnt.dll,DavSetCookie") and

  /* Access to named pipe via http */
  process.args : ("http*/print/pipe/*", "http*/pipe/spoolss", "http*/pipe/srvsvc")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Exploitation for Credential Access
    * ID: T1212
    * Reference URL: [https://attack.mitre.org/techniques/T1212/](https://attack.mitre.org/techniques/T1212/)




---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/service-disabled-via-registry-modification.html
---

# Service Disabled via Registry Modification [service-disabled-via-registry-modification]

Identifies attempts to modify services start settings using processes other than services.exe. Attackers may attempt to modify security and monitoring services to avoid detection or delay response.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.registry-*
* endgame-*

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
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Rule Type: BBR

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_981]

```js
registry where host.os.type == "windows" and event.type == "change" and
  registry.path : (
    "HKLM\\SYSTEM\\*ControlSet*\\Services\\*\\Start",
    "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Services\\*\\Start"
  ) and registry.data.strings : ("3", "4") and
  not
    (
      process.name : "services.exe" and user.id : "S-1-5-18"
    )
  and not registry.path : "HKLM\\SYSTEM\\ControlSet001\\Services\\MrxSmb10\\Start"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Modify Registry
    * ID: T1112
    * Reference URL: [https://attack.mitre.org/techniques/T1112/](https://attack.mitre.org/techniques/T1112/)

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Service Stop
    * ID: T1489
    * Reference URL: [https://attack.mitre.org/techniques/T1489/](https://attack.mitre.org/techniques/T1489/)




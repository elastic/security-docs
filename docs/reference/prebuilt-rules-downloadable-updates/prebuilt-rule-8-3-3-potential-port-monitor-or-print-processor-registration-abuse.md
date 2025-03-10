---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-potential-port-monitor-or-print-processor-registration-abuse.html
---

# Potential Port Monitor or Print Processor Registration Abuse [prebuilt-rule-8-3-3-potential-port-monitor-or-print-processor-registration-abuse]

Identifies port monitor and print processor registry modifications. Adversaries may abuse port monitor and print processors to run malicious DLLs during system boot that will be executed as SYSTEM for privilege escalation and/or persistence, if permissions allow writing a fully-qualified pathname for that DLL.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.welivesecurity.com/2020/05/21/no-game-over-winnti-group/](https://www.welivesecurity.com/2020/05/21/no-game-over-winnti-group/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Privilege Escalation

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3750]

```js
registry where event.type in ("creation", "change") and
  registry.path : ("HKLM\\SYSTEM\\*ControlSet*\\Control\\Print\\Monitors\\*",
    "HKLM\\SYSTEM\\*ControlSet*\\Control\\Print\\Environments\\Windows*\\Print Processors\\*") and
  registry.data.strings : "*.dll" and
  /* exclude SYSTEM SID - look for changes by non-SYSTEM user */
  not user.id : "S-1-5-18"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Boot or Logon Autostart Execution
    * ID: T1547
    * Reference URL: [https://attack.mitre.org/techniques/T1547/](https://attack.mitre.org/techniques/T1547/)

* Sub-technique:

    * Name: Port Monitors
    * ID: T1547.010
    * Reference URL: [https://attack.mitre.org/techniques/T1547/010/](https://attack.mitre.org/techniques/T1547/010/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Boot or Logon Autostart Execution
    * ID: T1547
    * Reference URL: [https://attack.mitre.org/techniques/T1547/](https://attack.mitre.org/techniques/T1547/)

* Sub-technique:

    * Name: Port Monitors
    * ID: T1547.010
    * Reference URL: [https://attack.mitre.org/techniques/T1547/010/](https://attack.mitre.org/techniques/T1547/010/)




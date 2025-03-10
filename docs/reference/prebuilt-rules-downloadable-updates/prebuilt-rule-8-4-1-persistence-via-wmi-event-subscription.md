---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-persistence-via-wmi-event-subscription.html
---

# Persistence via WMI Event Subscription [prebuilt-rule-8-4-1-persistence-via-wmi-event-subscription]

An adversary can use Windows Management Instrumentation (WMI) to install event filters, providers, consumers, and bindings that execute code when a defined event occurs. Adversaries may use the capabilities of WMI to subscribe to an event and execute arbitrary code when that event occurs, providing persistence on a system.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* winlogbeat-*
* logs-windows.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/security-labs/hunting-for-persistence-using-elastic-security-part-1](https://www.elastic.co/security-labs/hunting-for-persistence-using-elastic-security-part-1)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Persistence

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2840]



## Rule query [_rule_query_3243]

```js
process where event.type == "start" and
  (process.name : "wmic.exe" or process.pe.original_file_name == "wmic.exe") and
  process.args : "create" and
  process.args : ("ActiveScriptEventConsumer", "CommandLineEventConsumer")
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

    * Name: Windows Management Instrumentation Event Subscription
    * ID: T1546.003
    * Reference URL: [https://attack.mitre.org/techniques/T1546/003/](https://attack.mitre.org/techniques/T1546/003/)




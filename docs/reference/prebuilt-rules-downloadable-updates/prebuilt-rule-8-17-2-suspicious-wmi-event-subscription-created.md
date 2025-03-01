---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-2-suspicious-wmi-event-subscription-created.html
---

# Suspicious WMI Event Subscription Created [prebuilt-rule-8-17-2-suspicious-wmi-event-subscription-created]

Detects the creation of a WMI Event Subscription. Attackers can abuse this mechanism for persistence or to elevate to SYSTEM privileges.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-windows.sysmon_operational-*
* logs-endpoint.events.api-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf](https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf)
* [https://medium.com/threatpunter/detecting-removing-wmi-persistence-60ccbb7dff96](https://medium.com/threatpunter/detecting-removing-wmi-persistence-60ccbb7dff96)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Data Source: Sysmon
* Data Source: Elastic Defend

**Version**: 306

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4818]

```js
any where
 (
   (event.dataset == "windows.sysmon_operational" and event.code == "21" and
    winlog.event_data.Operation : "Created" and winlog.event_data.Consumer : ("*subscription:CommandLineEventConsumer*", "*subscription:ActiveScriptEventConsumer*")) or

   (event.dataset == "endpoint.events.api" and event.provider == "Microsoft-Windows-WMI-Activity" and process.Ext.api.name == "IWbemServices::PutInstance" and
    process.Ext.api.parameters.consumer_type in ("ActiveScriptEventConsumer", "CommandLineEventConsumer"))
 )
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




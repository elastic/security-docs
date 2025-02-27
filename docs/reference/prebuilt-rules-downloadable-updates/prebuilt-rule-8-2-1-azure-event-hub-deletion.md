---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-azure-event-hub-deletion.html
---

# Azure Event Hub Deletion [prebuilt-rule-8-2-1-azure-event-hub-deletion]

Identifies an Event Hub deletion in Azure. An Event Hub is an event processing service that ingests and processes large volumes of events and data. An adversary may delete an Event Hub in an attempt to evade detection.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-azure*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-25m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-about](https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-about)
* [https://azure.microsoft.com/en-in/services/event-hubs/](https://azure.microsoft.com/en-in/services/event-hubs/)
* [https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-features](https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-features)

**Tags**:

* Elastic
* Cloud
* Azure
* Continuous Monitoring
* SecOps
* Log Auditing

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1897]



## Rule query [_rule_query_2182]

```js
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.EVENTHUB/NAMESPACES/EVENTHUBS/DELETE" and event.outcome:(Success or success)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Sub-technique:

    * Name: Disable or Modify Tools
    * ID: T1562.001
    * Reference URL: [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)




---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-azure-network-watcher-deletion.html
---

# Azure Network Watcher Deletion [prebuilt-rule-8-2-1-azure-network-watcher-deletion]

Identifies the deletion of a Network Watcher in Azure. Network Watchers are used to monitor, diagnose, view metrics, and enable or disable logs for resources in an Azure virtual network. An adversary may delete a Network Watcher in an attempt to evade defenses.

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

* [https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-monitoring-overview](https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-monitoring-overview)

**Tags**:

* Elastic
* Cloud
* Azure
* Continuous Monitoring
* SecOps
* Network Security

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1901]



## Rule query [_rule_query_2186]

```js
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.NETWORK/NETWORKWATCHERS/DELETE" and event.outcome:(Success or success)
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




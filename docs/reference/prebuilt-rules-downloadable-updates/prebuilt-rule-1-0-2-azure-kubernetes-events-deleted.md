---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-azure-kubernetes-events-deleted.html
---

# Azure Kubernetes Events Deleted [prebuilt-rule-1-0-2-azure-kubernetes-events-deleted]

Identifies when events are deleted in Azure Kubernetes. Kubernetes events are objects that log any state changes. Example events are a container creation, an image pull, or a pod scheduling on a node. An adversary may delete events in Azure Kubernetes in an attempt to evade detection.

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

* [https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes](https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes)

**Tags**:

* Elastic
* Cloud
* Azure
* Continuous Monitoring
* SecOps
* Log Auditing

**Version**: 4

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1421]

## Config

The Azure Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Rule query [_rule_query_1652]

```js
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/EVENTS.K8S.IO/EVENTS/DELETE" and
event.outcome:(Success or success)
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




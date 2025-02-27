---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-azure-alert-suppression-rule-created-or-modified.html
---

# Azure Alert Suppression Rule Created or Modified [prebuilt-rule-1-0-2-azure-alert-suppression-rule-created-or-modified]

Identifies the creation of suppression rules in Azure. Suppression rules are a mechanism used to suppress alerts previously identified as false positives or too noisy to be in production. This mechanism can be abused or mistakenly configured, resulting in defense evasions and loss of security visibility.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-azure*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-25m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations](https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations)
* [https://docs.microsoft.com/en-us/rest/api/securitycenter/alerts-suppression-rules/update](https://docs.microsoft.com/en-us/rest/api/securitycenter/alerts-suppression-rules/update)

**Tags**:

* Elastic
* Cloud
* Azure
* Continuous Monitoring
* SecOps
* Configuration Audit

**Version**: 2

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1423]

## Config

The Azure Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Rule query [_rule_query_1654]

```js
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.SECURITY/ALERTSSUPPRESSIONRULES/WRITE" and
event.outcome: "success"
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




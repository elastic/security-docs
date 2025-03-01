---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-1-azure-automation-runbook-deleted.html
---

# Azure Automation Runbook Deleted [prebuilt-rule-8-3-1-azure-automation-runbook-deleted]

Identifies when an Azure Automation runbook is deleted. An adversary may delete an Azure Automation runbook in order to disrupt their target’s automated business operations or to remove a malicious runbook for defense evasion.

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

* [https://powerzure.readthedocs.io/en/latest/Functions/operational.html#create-backdoor](https://powerzure.readthedocs.io/en/latest/Functions/operational.md#create-backdoor)
* [https://github.com/hausec/PowerZure](https://github.com/hausec/PowerZure)
* [https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a](https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a)
* [https://azure.microsoft.com/en-in/blog/azure-automation-runbook-management/](https://azure.microsoft.com/en-in/blog/azure-automation-runbook-management/)

**Tags**:

* Elastic
* Cloud
* Azure
* Continuous Monitoring
* SecOps
* Configuration Audit
* Defense Evasion

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2281]



## Rule query [_rule_query_2619]

```js
event.dataset:azure.activitylogs and
    azure.activitylogs.operation_name:"MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/DELETE" and
    event.outcome:(Success or success)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)




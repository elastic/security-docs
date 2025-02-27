---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-azure-automation-runbook-created-or-modified.html
---

# Azure Automation Runbook Created or Modified [prebuilt-rule-8-2-1-azure-automation-runbook-created-or-modified]

Identifies when an Azure Automation runbook is created or modified. An adversary may create or modify an Azure Automation runbook to execute malicious code and maintain persistence in their target’s environment.

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

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1915]



## Rule query [_rule_query_2200]

```js
event.dataset:azure.activitylogs and
  azure.activitylogs.operation_name:
  (
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/DRAFT/WRITE" or
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/WRITE" or
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/PUBLISH/ACTION"
  ) and
  event.outcome:(Success or success)
```



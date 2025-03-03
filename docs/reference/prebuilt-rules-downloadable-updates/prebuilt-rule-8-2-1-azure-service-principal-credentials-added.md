---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-azure-service-principal-credentials-added.html
---

# Azure Service Principal Credentials Added [prebuilt-rule-8-2-1-azure-service-principal-credentials-added]

Identifies when new Service Principal credentials have been added in Azure. In most organizations, credentials will be added to service principals infrequently. Hijacking an application (by adding a rogue secret or certificate) with granted permissions will allow the attacker to access data that is normally protected by MFA requirements.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-azure*

**Severity**: medium

**Risk score**: 47

**Runs every**: 10m

**Searches indices from**: now-25m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.fireeye.com/content/dam/collateral/en/wp-m-unc2452.pdf](https://www.fireeye.com/content/dam/collateral/en/wp-m-unc2452.pdf)

**Tags**:

* Elastic
* Cloud
* Azure
* Continuous Monitoring
* SecOps
* Identity and Access

**Version**: 4

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1905]



## Rule query [_rule_query_2190]

```js
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Add service principal credentials" and event.outcome:(success or Success)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Resource Hijacking
    * ID: T1496
    * Reference URL: [https://attack.mitre.org/techniques/T1496/](https://attack.mitre.org/techniques/T1496/)




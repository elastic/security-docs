---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-azure-frontdoor-web-application-firewall-waf-policy-deleted.html
---

# Azure Frontdoor Web Application Firewall (WAF) Policy Deleted [prebuilt-rule-8-2-1-azure-frontdoor-web-application-firewall-waf-policy-deleted]

Identifies the deletion of a Frontdoor Web Application Firewall (WAF) Policy in Azure. An adversary may delete a Frontdoor Web Application Firewall (WAF) Policy in an attempt to evade defenses and/or to eliminate barriers to their objective.

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

* [https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#networking](https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#networking)

**Tags**:

* Elastic
* Cloud
* Azure
* Continuous Monitoring
* SecOps
* Network Security

**Version**: 4

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1899]



## Rule query [_rule_query_2184]

```js
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.NETWORK/FRONTDOORWEBAPPLICATIONFIREWALLPOLICIES/DELETE" and event.outcome:(Success or success)
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




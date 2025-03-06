---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-aws-route-53-domain-transfer-lock-disabled.html
---

# AWS Route 53 Domain Transfer Lock Disabled [prebuilt-rule-8-2-1-aws-route-53-domain-transfer-lock-disabled]

Identifies when a transfer lock was removed from a Route 53 domain. It is recommended to refrain from performing this action unless intending to transfer the domain to a different registrar.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws*

**Severity**: low

**Risk score**: 21

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/Route53/latest/APIReference/API_Operations_Amazon_Route_53.html](https://docs.aws.amazon.com/Route53/latest/APIReference/API_Operations_Amazon_Route_53.html)
* [https://docs.aws.amazon.com/Route53/latest/APIReference/API_domains_DisableDomainTransferLock.html](https://docs.aws.amazon.com/Route53/latest/APIReference/API_domains_DisableDomainTransferLock.html)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Asset Visibility

**Version**: 3

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1878]



## Rule query [_rule_query_2163]

```js
event.dataset:aws.cloudtrail and event.provider:route53.amazonaws.com and event.action:DisableDomainTransferLock and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)




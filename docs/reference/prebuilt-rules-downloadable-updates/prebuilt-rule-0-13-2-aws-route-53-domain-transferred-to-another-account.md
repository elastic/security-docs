---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-13-2-aws-route-53-domain-transferred-to-another-account.html
---

# AWS Route 53 Domain Transferred to Another Account [prebuilt-rule-0-13-2-aws-route-53-domain-transferred-to-another-account]

Identifies when a request has been made to transfer a Route 53 domain to another AWS account.

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

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Asset Visibility

**Version**: 1

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1233]

## Config

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Rule query [_rule_query_1278]

```js
event.dataset:aws.cloudtrail and event.provider:route53.amazonaws.com and event.action:TransferDomainToAnotherAwsAccount and event.outcome:success
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




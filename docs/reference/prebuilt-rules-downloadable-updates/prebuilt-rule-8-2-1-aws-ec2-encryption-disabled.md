---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-aws-ec2-encryption-disabled.html
---

# AWS EC2 Encryption Disabled [prebuilt-rule-8-2-1-aws-ec2-encryption-disabled]

Identifies disabling of Amazon Elastic Block Store (EBS) encryption by default in the current region. Disabling encryption by default does not change the encryption status of your existing volumes.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws*

**Severity**: medium

**Risk score**: 47

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html)
* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/disable-ebs-encryption-by-default.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/disable-ebs-encryption-by-default.html)
* [https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DisableEbsEncryptionByDefault.html](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DisableEbsEncryptionByDefault.html)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Data Protection

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1856]



## Rule query [_rule_query_2146]

```js
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:DisableEbsEncryptionByDefault and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Data Manipulation
    * ID: T1565
    * Reference URL: [https://attack.mitre.org/techniques/T1565/](https://attack.mitre.org/techniques/T1565/)

* Sub-technique:

    * Name: Stored Data Manipulation
    * ID: T1565.001
    * Reference URL: [https://attack.mitre.org/techniques/T1565/001/](https://attack.mitre.org/techniques/T1565/001/)




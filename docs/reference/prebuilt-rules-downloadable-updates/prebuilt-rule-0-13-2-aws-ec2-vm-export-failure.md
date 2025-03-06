---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-13-2-aws-ec2-vm-export-failure.html
---

# AWS EC2 VM Export Failure [prebuilt-rule-0-13-2-aws-ec2-vm-export-failure]

Identifies an attempt to export an AWS EC2 instance. A virtual machine (VM) export may indicate an attempt to extract or exfiltrate information.

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

* [https://docs.aws.amazon.com/vm-import/latest/userguide/vmexport.html#export-instance](https://docs.aws.amazon.com/vm-import/latest/userguide/vmexport.html#export-instance)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Asset Visibility

**Version**: 2

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1235]

## Config

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Rule query [_rule_query_1287]

```js
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:CreateInstanceExportTask and event.outcome:failure
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Exfiltration
    * ID: TA0010
    * Reference URL: [https://attack.mitre.org/tactics/TA0010/](https://attack.mitre.org/tactics/TA0010/)

* Technique:

    * Name: Transfer Data to Cloud Account
    * ID: T1537
    * Reference URL: [https://attack.mitre.org/techniques/T1537/](https://attack.mitre.org/techniques/T1537/)

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Data from Local System
    * ID: T1005
    * Reference URL: [https://attack.mitre.org/techniques/T1005/](https://attack.mitre.org/techniques/T1005/)




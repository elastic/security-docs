---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-ec2-vm-export-failure.html
---

# AWS EC2 VM Export Failure [aws-ec2-vm-export-failure]

Identifies an attempt to export an AWS EC2 instance. A virtual machine (VM) export may indicate an attempt to extract or exfiltrate information.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: low

**Risk score**: 21

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/vm-import/latest/userguide/vmexport.html#export-instance](https://docs.aws.amazon.com/vm-import/latest/userguide/vmexport.md#export-instance)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Use Case: Asset Visibility
* Tactic: Exfiltration
* Tactic: Collection
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_36]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS EC2 VM Export Failure**

AWS EC2 allows users to export virtual machines for backup or migration. However, adversaries might exploit this feature to exfiltrate sensitive data by exporting VMs to unauthorized locations. The detection rule monitors failed export attempts, focusing on specific AWS CloudTrail events, to identify potential exfiltration activities, thereby alerting security teams to investigate further.

**Possible investigation steps**

* Review the AWS CloudTrail logs for the specific event.action: CreateInstanceExportTask with event.outcome: failure to gather details about the failed export attempt, including timestamps, source IP addresses, and user identities involved.
* Investigate the IAM user or role associated with the failed export attempt to determine if the action was authorized or if there are any signs of compromised credentials.
* Check the AWS account’s export policies and permissions to ensure they are configured correctly and restrict unauthorized export attempts.
* Analyze any recent changes in the AWS environment, such as new IAM roles or policy modifications, that could be related to the failed export attempt.
* Correlate the failed export attempt with other security events or alerts in the environment to identify any patterns or potential coordinated activities indicating a broader threat.

**False positive analysis**

* Routine backup operations may trigger the rule if they involve failed export attempts. To manage this, identify and whitelist specific IAM roles or users that regularly perform legitimate backup tasks.
* Development and testing environments often involve frequent export attempts for non-production instances. Exclude these environments by tagging instances appropriately and adjusting the detection rule to ignore these tags.
* Misconfigured export tasks due to incorrect permissions or settings can lead to false positives. Regularly review and update IAM policies and export configurations to ensure they align with intended operations.
* Automated scripts or tools that manage EC2 instances might occasionally fail due to transient issues, causing false alerts. Monitor and log these scripts' activities to distinguish between expected failures and potential threats.

**Response and remediation**

* Immediately isolate the affected AWS account to prevent further unauthorized export attempts. This can be done by restricting permissions or temporarily suspending the account.
* Review and revoke any suspicious or unauthorized IAM roles or policies that may have been used to initiate the failed export attempt.
* Conduct a thorough audit of recent AWS CloudTrail logs to identify any other unusual activities or patterns that may indicate a broader compromise.
* Notify the security operations team and relevant stakeholders about the incident for further investigation and potential escalation.
* Implement additional monitoring and alerting for successful and failed VM export attempts to ensure rapid detection of similar activities in the future.
* Enhance IAM policies to enforce the principle of least privilege, ensuring only authorized users have the necessary permissions to export EC2 instances.
* Consider enabling AWS Config rules to continuously monitor and enforce compliance with security best practices related to EC2 instance exports.


## Setup [_setup_22]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_37]

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




---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-ec2-encryption-disabled.html
---

# AWS EC2 Encryption Disabled [aws-ec2-encryption-disabled]

Identifies disabling of Amazon Elastic Block Store (EBS) encryption by default in the current region. Disabling encryption by default does not change the encryption status of your existing volumes.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.md)
* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/disable-ebs-encryption-by-default.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/disable-ebs-encryption-by-default.md)
* [https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DisableEbsEncryptionByDefault.html](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DisableEbsEncryptionByDefault.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS EC2
* Tactic: Impact
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_25]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS EC2 Encryption Disabled**

Amazon EC2’s EBS encryption ensures data at rest is secure by default. Disabling this feature can expose sensitive data, making it vulnerable to unauthorized access. Adversaries might exploit this by disabling encryption to access or manipulate data without detection. The detection rule monitors CloudTrail logs for successful attempts to disable EBS encryption, alerting security teams to potential misuse.

**Possible investigation steps**

* Review the CloudTrail logs for the specific event.action: DisableEbsEncryptionByDefault to identify the user or role that initiated the action.
* Check the event.provider: ec2.amazonaws.com logs to gather additional context about the environment and any related activities around the time of the event.
* Investigate the IAM policies and permissions associated with the user or role to determine if they have the necessary permissions to disable EBS encryption and if those permissions are appropriate.
* Assess the event.outcome: success to confirm that the action was completed successfully and identify any subsequent actions taken by the same user or role.
* Examine the AWS account’s security settings and configurations to ensure that no other security features have been altered or disabled.
* Contact the user or team responsible for the action to understand the rationale behind disabling EBS encryption and verify if it aligns with organizational policies.

**False positive analysis**

* Routine administrative actions may trigger alerts if encryption is disabled for testing or configuration purposes. To manage this, create exceptions for specific IAM roles or users known to perform these tasks regularly.
* Automated scripts or tools that disable encryption for specific workflows might cause false positives. Identify these scripts and exclude their associated actions from triggering alerts by using specific tags or identifiers.
* Changes in regional settings or policies that temporarily disable encryption could be misinterpreted as threats. Monitor these changes and adjust the detection rule to account for legitimate policy updates.
* Scheduled maintenance or updates that require temporary encryption disabling should be documented and excluded from alerts by setting time-based exceptions during known maintenance windows.

**Response and remediation**

* Immediately isolate the affected EC2 instances to prevent further unauthorized access or data manipulation. This can be done by modifying security group rules or network ACLs to restrict access.
* Re-enable EBS encryption by default in the affected region to ensure that all new volumes are encrypted. This can be done through the AWS Management Console or AWS CLI.
* Conduct a thorough review of recent changes in the AWS environment to identify any unauthorized modifications or access patterns. Focus on CloudTrail logs for any suspicious activity related to EBS encryption settings.
* Notify the security operations team and relevant stakeholders about the incident, providing them with details of the alert and any initial findings.
* Implement additional monitoring and alerting for any future attempts to disable EBS encryption by default, ensuring that security teams are promptly notified of similar activities.
* Review and update IAM policies to ensure that only authorized personnel have the necessary permissions to modify EBS encryption settings, reducing the risk of accidental or malicious changes.
* If any data manipulation is detected, initiate data recovery procedures to restore affected data from backups, ensuring data integrity and availability.


## Setup [_setup_17]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_25]

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




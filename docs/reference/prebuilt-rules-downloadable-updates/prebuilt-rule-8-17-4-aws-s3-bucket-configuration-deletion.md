---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-s3-bucket-configuration-deletion.html
---

# AWS S3 Bucket Configuration Deletion [prebuilt-rule-8-17-4-aws-s3-bucket-configuration-deletion]

Identifies the deletion of various Amazon Simple Storage Service (S3) bucket configuration components.

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

* [https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketPolicy.html](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketPolicy.md)
* [https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketReplication.html](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketReplication.md)
* [https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketCors.html](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketCors.md)
* [https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketEncryption.html](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketEncryption.md)
* [https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketLifecycle.html](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketLifecycle.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Use Case: Asset Visibility
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 208

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3994]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS S3 Bucket Configuration Deletion**

Amazon S3 is a scalable storage service where configurations like policies, replication, and encryption ensure data security and compliance. Adversaries may delete these configurations to evade defenses, disrupt data protection, or conceal malicious activities. The detection rule monitors successful deletions of these configurations, signaling potential defense evasion attempts by correlating specific CloudTrail events.

**Possible investigation steps**

* Review the CloudTrail logs for the specific event.provider:s3.amazonaws.com and event.action values to identify the user or role responsible for the deletion actions.
* Examine the event.outcome:success field to confirm that the deletion actions were completed successfully and not attempted or failed.
* Investigate the IAM policies and permissions associated with the user or role identified to determine if they have legitimate access to perform such deletions.
* Check for any recent changes in IAM roles or policies that might have inadvertently granted excessive permissions.
* Correlate the timing of the deletion events with other suspicious activities or alerts in the AWS environment to identify potential patterns or coordinated actions.
* Assess the impact of the deleted configurations on data security and compliance, and determine if any critical data protection mechanisms were affected.

**False positive analysis**

* Routine administrative actions by authorized personnel may trigger alerts when they update or remove bucket configurations as part of regular maintenance. To manage this, create exceptions for specific user roles or IAM users known to perform these tasks regularly.
* Automated scripts or tools used for infrastructure management might delete and recreate bucket configurations as part of their operation. Identify these scripts and exclude their associated actions from triggering alerts by using specific identifiers or tags.
* Scheduled policy updates or compliance checks that involve temporary removal of configurations can also result in false positives. Implement time-based exceptions for these known activities to prevent unnecessary alerts.
* Development and testing environments often undergo frequent configuration changes, which can mimic suspicious behavior. Exclude these environments from the rule by using environment-specific tags or identifiers.

**Response and remediation**

* Immediately revoke any unauthorized access to the affected S3 bucket by reviewing and updating the bucket’s access policies and permissions.
* Restore the deleted configurations by applying the latest known good configuration settings for policies, replication, encryption, and other affected components.
* Conduct a thorough audit of recent IAM activity to identify any unauthorized or suspicious actions related to the S3 bucket configurations.
* Escalate the incident to the security operations team for further investigation and to determine if additional AWS resources or accounts have been compromised.
* Implement additional monitoring and alerting for any future unauthorized configuration changes to S3 buckets, focusing on the specific actions identified in the detection rule.
* Review and enhance IAM policies to enforce the principle of least privilege, ensuring only authorized users have the necessary permissions to modify S3 bucket configurations.
* Coordinate with the incident response team to assess the impact of the configuration deletions on data security and compliance, and take necessary steps to mitigate any identified risks.


## Setup [_setup_926]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5011]

```js
event.dataset:aws.cloudtrail and event.provider:s3.amazonaws.com and
  event.action:(DeleteBucketPolicy or DeleteBucketReplication or DeleteBucketCors or
                DeleteBucketEncryption or DeleteBucketLifecycle)
  and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Indicator Removal
    * ID: T1070
    * Reference URL: [https://attack.mitre.org/techniques/T1070/](https://attack.mitre.org/techniques/T1070/)




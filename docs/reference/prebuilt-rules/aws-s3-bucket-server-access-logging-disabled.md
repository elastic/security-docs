---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-s3-bucket-server-access-logging-disabled.html
---

# AWS S3 Bucket Server Access Logging Disabled [aws-s3-bucket-server-access-logging-disabled]

Identifies when server access logging is disabled for an Amazon S3 bucket. Server access logs provide a detailed record of requests made to an S3 bucket. When server access logging is disabled for a bucket, it could indicate an adversary’s attempt to impair defenses by disabling logs that contain evidence of malicious activity.

**Rule type**: eql

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-6m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLogging.html](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLogging.md)
* [https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-server-access-logging.html](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-server-access-logging.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: Amazon S3
* Use Case: Asset Visibility
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_88]

**Triage and analysis**

**Investigating AWS S3 Bucket Server Access Logging Disabled**

This rule detects when server access logging is disabled for an S3 bucket in AWS. Such configurations could potentially hide evidence of unauthorized access or malicious activity by preventing the recording of those requests.

**Detailed Investigation Steps**

* ***Review the Affected S3 Bucket***: Check the bucket details (`bucketName`) where server access logging has been disabled.
* Determine the contents and importance of the data stored in this bucket to assess the impact of disabled logging.
* ***Review User Identity and Activity***:
* Investigate the user (`user_identity.arn`) who made the change. Determine whether this user’s role typically involves managing S3 bucket configurations.
* Examine the authentication method and whether the access key used (`access_key_id`) is routinely used for such configurations or if it has deviated from normal usage patterns.
* Contact the account owner and confirm whether they are aware of this activity.
* Considering the source IP address and geolocation of the user who issued the command:
* Do they look normal for the calling user?
* If the source is an EC2 IP address, is it associated with an EC2 instance in one of your accounts or is the source IP from an EC2 instance that’s not under your control?
* If it is an authorized EC2 instance, is the activity associated with normal behavior for the instance role or roles? Are there any other alerts or signs of suspicious activity involving this instance?
* ***Contextualize with Recent Changes***: Compare this event against recent changes in S3 configurations. Look for any other recent permissions changes or unusual administrative actions.
* ***Correlate with Other Activities***: Search for related CloudTrail events before and after this change to see if the same actor or IP address engaged in other potentially suspicious activities.
* Assess whether this behavior is prevalent in the environment by looking for similar occurrences involving other users.

**False Positive Analysis**

* Verify the operational requirements that might necessitate disabling access logging, especially in environments where data retention policies are strictly governed for compliance and cost-saving reasons.

**Response and Remediation**

* ***Immediate Review***: If the change was unauthorized, consider reverting the change immediately to prevent potential data loss.
* ***Enhance Monitoring***: Implement monitoring to alert on changes to logging configurations across your S3 environments.
* ***User Education***: Ensure that users with access to critical resources like S3 buckets are aware of the best practices and company policies regarding data retention and security.

**Additional Information**

For further guidance on monitoring Amazon S3 and ensuring compliance with organizational data retention and security policies, refer to the AWS official documentation on [Monitoring Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/monitoring-overview.md).


## Rule query [_rule_query_92]

```js
any where event.dataset == "aws.cloudtrail"
   and event.action == "PutBucketLogging"
   and event.outcome == "success"
   and not stringContains(aws.cloudtrail.request_parameters, "LoggingEnabled")
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

    * Name: Disable or Modify Cloud Logs
    * ID: T1562.008
    * Reference URL: [https://attack.mitre.org/techniques/T1562/008/](https://attack.mitre.org/techniques/T1562/008/)




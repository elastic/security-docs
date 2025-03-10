---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-s3-bucket-policy-added-to-share-with-external-account.html
---

# AWS S3 Bucket Policy Added to Share with External Account [prebuilt-rule-8-17-4-aws-s3-bucket-policy-added-to-share-with-external-account]

Identifies an AWS S3 bucket policy change to share permissions with an external account. Adversaries may attempt to backdoor an S3 bucket by sharing it with an external account. This can be used to exfiltrate data or to provide access to other adversaries. This rule identifies changes to a bucket policy via the `PutBucketPolicy` API call where the policy includes an `Effect=Allow` statement that does not contain the AWS account ID of the bucket owner.

**Rule type**: eql

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://stratus-red-team.cloud/attack-techniques/AWS/aws.exfiltration.s3-backdoor-bucket-policy/](https://stratus-red-team.cloud/attack-techniques/AWS/aws.exfiltration.s3-backdoor-bucket-policy/)
* [https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketPolicy.html](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketPolicy.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS S3
* Use Case: Threat Detection
* Tactic: Exfiltration
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4017]

**Triage and analysis**

**Investigating AWS S3 Bucket Policy Added to Share with External Account**

This rule detects when an AWS S3 bucket policy is changed to share permissions with an external account. Adversaries may attempt to backdoor an S3 bucket by sharing it with an external account to exfiltrate data or provide access to other adversaries. This rule identifies changes to a bucket policy via the `PutBucketPolicy` API call where the policy includes an `Effect=Allow` statement that does not contain the AWS account ID of the bucket owner.

**Possible Investigation Steps:**

* ***Identify the Actor***: Review the `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.access_key_id` fields to identify who made the change. Verify if this actor typically performs such actions and if they have the necessary permissions.
* ***Review the Request Details***: Examine the `aws.cloudtrail.request_parameters` to understand the specific changes made to the bucket policy. Look for any unusual parameters that could suggest unauthorized or malicious modifications.
* ***Analyze the Source of the Request***: Investigate the `source.ip` and `source.geo` fields to determine the geographical origin of the request. An external or unexpected location might indicate compromised credentials or unauthorized access.
* ***Contextualize with Timestamp***: Use the `@timestamp` field to check when the change occurred. Modifications during non-business hours or outside regular maintenance windows might require further scrutiny.
* ***Correlate with Other Activities***: Search for related CloudTrail events before and after this change to see if the same actor or IP address engaged in other potentially suspicious activities.

**False Positive Analysis:**

* ***Legitimate Administrative Actions***: Confirm if the bucket policy change aligns with scheduled updates, development activities, or legitimate administrative tasks documented in change management systems.
* ***Consistency Check***: Compare the action against historical data of similar actions performed by the user or within the organization. If the action is consistent with past legitimate activities, it might indicate a false alarm.
* ***Verify through Outcomes***: Check the `aws.cloudtrail.response_elements` and the `event.outcome` to confirm if the change was successful and intended according to policy.

**Response and Remediation:**

* ***Immediate Review and Reversal if Necessary***: If the change was unauthorized, update the bucket policy to remove any unauthorized permissions and restore it to its previous state.
* ***Enhance Monitoring and Alerts***: Adjust monitoring systems to alert on similar actions, especially those involving sensitive data or permissions.
* ***Educate and Train***: Provide additional training to users with administrative rights on the importance of security best practices concerning bucket policy management and sharing permissions.
* ***Audit Bucket Policies and Permissions***: Conduct a comprehensive audit of all bucket policies and associated permissions to ensure they adhere to the principle of least privilege.
* ***Incident Response***: If there’s an indication of malicious intent or a security breach, initiate the incident response protocol to mitigate any damage and prevent future occurrences.

**Additional Information:**

For further guidance on managing S3 bucket policies and securing AWS environments, refer to the [AWS S3 documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-cloudtrail-logging-for-s3.md) and AWS best practices for security.


## Setup [_setup_933]

**Setup**

S3 data event types must be collected in the AWS CloudTrail logs. Please refer to [AWS documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-cloudtrail-logging-for-s3.md) for more information.


## Rule query [_rule_query_5034]

```js
any where event.dataset == "aws.cloudtrail"
    and event.provider == "s3.amazonaws.com"
    and event.action == "PutBucketPolicy" and event.outcome == "success"
    and stringContains(aws.cloudtrail.request_parameters, "Effect=Allow")
    and not stringContains(aws.cloudtrail.request_parameters, aws.cloudtrail.recipient_account_id)
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




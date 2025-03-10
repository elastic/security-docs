---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/excessive-aws-s3-object-encryption-with-sse-c.html
---

# Excessive AWS S3 Object Encryption with SSE-C [excessive-aws-s3-object-encryption-with-sse-c]

Identifies a high-volume of AWS S3 objects stored in a bucket using using Server-Side Encryption with Customer-Provided Keys (SSE-C). Adversaries with compromised AWS credentials can encrypt objects in an S3 bucket using their own encryption keys, rendering the objects unreadable or recoverable without the key. This can be used as a form of ransomware to extort the bucket owner for the decryption key. This is a [Threshold](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#create-threshold-rule) rule that flags when this behavior is observed for a specific bucket more than 15 times in a short time-window.

**Rule type**: threshold

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.halcyon.ai/blog/abusing-aws-native-services-ransomware-encrypting-s3-buckets-with-sse-c](https://www.halcyon.ai/blog/abusing-aws-native-services-ransomware-encrypting-s3-buckets-with-sse-c)
* [https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerSideEncryptionCustomerKeys.html](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerSideEncryptionCustomerKeys.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS S3
* Resources: Investigation Guide
* Use Case: Threat Detection
* Tactic: Impact

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_303]

**Triage and Analysis**

**Investigating Excessive AWS S3 Object Encryption with SSE-C**

This rule identifies a high volume of objects being encrypted using Server-Side Encryption with Customer-Provided Keys (SSE-C) in AWS S3. This could indicate malicious activity, such as ransomware encrypting objects, rendering them inaccessible without the corresponding encryption keys.

**Possible Investigation Steps**

1. ***Identify the User and Source***:

    * Review the `aws.cloudtrail.user_identity.arn` to identify the IAM user or role performing the operation.
    * Cross-check the `source.ip` and `user_agent.original` fields for unusual IPs or user agents that could indicate unauthorized access.
    * Review the `aws.cloudtrail.user_identity.access_key_id` to identify the access key used. This could be a compromised key.

2. ***Examine the Targeted Resources***:

    * Check `aws.cloudtrail.flattened.request_parameters.bucketName` to identify the bucket involved.
    * Analyze the object key from `aws.cloudtrail.flattened.request_parameters.key`.

3. ***Evaluate Encryption Behavior***:

    * Confirm the encryption details in `aws.cloudtrail.flattened.request_parameters.x-amz-server-side-encryption-customer-algorithm` and `aws.cloudtrail.flattened.additional_eventdata.SSEApplied`.
    * Note if `SSEApplied` is `SSE-C`, which confirms encryption using a customer-provided key.

4. ***Correlate with Recent Events***:

    * Look for any suspicious activity in proximity to the encryption event, such as new access key creation, policy changes, or unusual access patterns from the same user or IP.
    * Identify `ListBucket` or `GetObject` operations on the same bucket to determine all affected objects.
    * For `PutObject` events, identify any other unusual objecs uploaded such as a ransom note.

5. ***Validate Access Permissions***:

    * Check the IAM policies and roles associated with the user to verify if they had legitimate access to encrypt objects.

6. ***Assess Impact***:

    * Identify the number of encrypted objects in the bucket by examining other similar events.
    * Determine if this encryption aligns with standard business practices or constitutes a deviation.


**False Positive Analysis**

* ***Legitimate Use Cases***:
* Confirm if SSE-C encryption is part of regular operations for compliance or data protection.
* Cross-reference known processes or users authorized for SSE-C encryption in the affected bucket.

**Response and Remediation**

1. ***Immediate Actions***:

    * Disable access keys or permissions for the user if unauthorized behavior is confirmed.
    * Rotate the bucket’s encryption configuration to mitigate further misuse.

2. ***Data Recovery***:

    * Attempt to identify and contact the party holding the SSE-C encryption keys if recovery is necessary.

3. ***Enhance Monitoring***:

    * Enable alerts for future SSE-C encryption attempts in critical buckets.
    * Review and tighten IAM policies for roles and users accessing S3.

4. ***Post-Incident Review***:

    * Audit logs for additional activities by the same user or IP.
    * Document findings and apply lessons learned to improve preventive measures.



## Setup [_setup_196]

AWS S3 data event types need to be enabled in the CloudTrail trail configuration.


## Rule query [_rule_query_317]

```js
event.dataset: "aws.cloudtrail"
    and event.provider: "s3.amazonaws.com"
    and event.action: "PutObject"
    and event.outcome: "success"
    and aws.cloudtrail.flattened.request_parameters.x-amz-server-side-encryption-customer-algorithm: "AES256"
    and aws.cloudtrail.flattened.additional_eventdata.SSEApplied: "SSE_C"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Data Encrypted for Impact
    * ID: T1486
    * Reference URL: [https://attack.mitre.org/techniques/T1486/](https://attack.mitre.org/techniques/T1486/)



